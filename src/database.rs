use chrono::Duration;
use diesel::{
    insert_into,
    pg::PgConnection,
    prelude::*,
    r2d2::{ConnectionManager, Pool},
};

use crate::utils::*;

pub struct Database {
    pool: Pool<ConnectionManager<PgConnection>>,
}

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use chrono::prelude::*;

use crate::{
    error::TimeError,
    models::*,
    requests::{DataRequest, HeartBeat},
};

impl Database {
    pub fn new(database_url: &str) -> Self {
        let manager = ConnectionManager::<PgConnection>::new(database_url);
        let pool = Pool::builder()
            .build(manager)
            .expect("Failed to create connection pool");
        Self { pool }
    }

    fn user_exists(&self, target_username: &str) -> Result<bool, TimeError> {
        use crate::schema::registered_users::dsl::*;
        Ok(registered_users
            .filter(username.eq(target_username))
            .first::<RegisteredUser>(&self.pool.get()?)
            .optional()?
            .is_some())
    }

    pub fn get_user_by_name(&self, target_username: &str) -> Result<RegisteredUser, TimeError> {
        use crate::schema::registered_users::dsl::*;
        Ok(registered_users
            .filter(username.eq(target_username))
            .first::<RegisteredUser>(&self.pool.get()?)?)
    }

    pub fn get_user_by_id(&self, userid: i32) -> Result<RegisteredUser, TimeError> {
        use crate::schema::registered_users::dsl::*;
        Ok(registered_users
            .filter(id.eq(userid))
            .first::<RegisteredUser>(&self.pool.get()?)?)
    }

    pub fn verify_user_password(&self, username: &str, password: &str) -> Result<Option<RegisteredUser>, TimeError> {
        let user = self.get_user_by_name(username)?;
        let argon2 = Argon2::default();
        let Ok(salt) = SaltString::new(&std::str::from_utf8(&user.salt).unwrap()) else {
            return Ok(None); // The user has no password
        };
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();
        if password_hash.hash.unwrap().as_bytes() == user.password {
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    pub fn regenerate_token(&self, userid: i32) -> Result<String, TimeError> {
        let token = crate::utils::generate_token();
        use crate::schema::registered_users::dsl::*;
        diesel::update(crate::schema::registered_users::table)
            .filter(id.eq(userid))
            .set(auth_token.eq(&token))
            .execute(&self.pool.get()?)?;
        Ok(token)
    }

    pub fn new_user(&self, username: &str, password: &str) -> Result<NewRegisteredUser, TimeError> {
        if self.user_exists(username)? {
            return Err(TimeError::UserExistsError);
        }
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();
        let token = generate_token();
        let hash = password_hash.hash.unwrap();
        let new_user = NewRegisteredUser {
            auth_token: token,
            registration_time: chrono::Local::now().naive_local(),
            username: username.to_string(),
            friend_code: generate_friend_code(),
            password: hash.as_bytes().to_vec(),
            salt: salt.as_bytes().to_vec(),
        };
        diesel::insert_into(crate::schema::registered_users::table)
            .values(&new_user)
            .execute(&self.pool.get()?)?;
        Ok(new_user)
    }

    pub fn change_username(&self, user: i32, new_username: &str) -> Result<(), TimeError> {
        if self.user_exists(new_username)? {
            return Err(TimeError::UserExistsError);
        }
        use crate::schema::registered_users::dsl::*;
        diesel::update(crate::schema::registered_users::table)
            .filter(id.eq(user))
            .set(username.eq(new_username))
            .execute(&self.pool.get()?)?;
        Ok(())
    }

    pub fn change_password(&self, user: i32, new_password: &str) -> Result<(), TimeError> {
        let new_salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(new_password.as_bytes(), &new_salt)
            .unwrap();
        let new_hash = password_hash.hash.unwrap();
        use crate::schema::registered_users::dsl::*;
        diesel::update(crate::schema::registered_users::table)
            .filter(id.eq(user))
            .set((
                password.eq(&new_hash.as_bytes()),
                salt.eq(new_salt.as_bytes()),
            ))
            .execute(&self.pool.get()?)?;
        Ok(())
    }

    pub fn get_user_by_token(&self, token: &str) -> Result<RegisteredUser, TimeError> {
        use crate::schema::registered_users::dsl::*;
        let user = registered_users
            .filter(auth_token.eq(token))
            .first::<RegisteredUser>(&self.pool.get()?)?;
        Ok(user)
    }

    pub fn add_activity(
        &self,
        updated_user_id: i32,
        heartbeat: HeartBeat,
        ctx_start_time: NaiveDateTime,
        ctx_duration: Duration,
    ) -> Result<(), TimeError> {
        use crate::schema::coding_activities::dsl::*;
        let activity = NewCodingActivity {
            user_id: updated_user_id,
            start_time: ctx_start_time,
            duration: ctx_duration.num_seconds() as i32,
            project_name: if heartbeat.project_name.is_some()
                && heartbeat.project_name.as_ref().unwrap().starts_with("tmp.")
            {
                Some(String::from("tmp"))
            } else {
                heartbeat.project_name
            },
            language: heartbeat.language,
            editor_name: heartbeat.editor_name,
            hostname: heartbeat.hostname,
        };
        diesel::insert_into(coding_activities)
            .values(activity)
            .execute(&self.pool.get()?)?;
        Ok(())
    }

    pub fn get_activity(
        &self,
        request: DataRequest,
        user: i32,
    ) -> Result<Vec<CodingActivity>, TimeError> {
        use crate::schema::coding_activities::dsl::*;
        let mut query = coding_activities.into_boxed().filter(user_id.eq(user));
        if let Some(from) = request.from {
            query = query.filter(start_time.ge(from.naive_local()));
        };
        if let Some(to) = request.to {
            query = query.filter(start_time.le(to.naive_local()));
        };
        if let Some(editor) = request.editor_name {
            query = query.filter(editor_name.eq(editor));
        };
        if let Some(project) = request.project_name {
            query = query.filter(project_name.eq(project));
        };
        if let Some(request_hostname) = request.hostname {
            query = query.filter(hostname.eq(request_hostname));
        };
        if let Some(request_language) = request.language {
            query = query.filter(language.eq(request_language));
        };
        if let Some(min_duration) = request.min_duration {
            query = query.filter(duration.ge(min_duration));
        };
        let res = query.load::<CodingActivity>(&self.pool.get()?).unwrap();
        Ok(res)
    }

    pub fn add_friend(&self, user: i32, friend: &str) -> Result<String, TimeError> {
        use crate::schema::registered_users::dsl::*;
        let Some((friend_id, friend_name)) = registered_users
            .filter(friend_code.eq(friend))
            .select((id,username))
            .first::<(i32,String)>(&self.pool.get()?)
            .optional()? else {
                return Err(TimeError::UserNotFound)
            };

        if friend_id == user {
            return Err(TimeError::CurrentUser);
        }

        let (lesser, greater) = if user < friend_id {
            (user, friend_id)
        } else {
            (friend_id, user)
        };

        insert_into(crate::schema::friend_relations::table)
            .values(crate::models::NewFriendRelation {
                lesser_id: lesser,
                greater_id: greater,
            })
            .execute(&self.pool.get()?)?;
        Ok(friend_name)
    }

    pub fn get_friends(&self, user: i32) -> Result<Vec<String>, TimeError> {
        use crate::schema::{
            friend_relations::dsl::{greater_id, lesser_id, friend_relations},
            registered_users::dsl::*,
        };
        let friends = friend_relations
            .filter(greater_id.eq(user).or(lesser_id.eq(user)))
            .load::<FriendRelation>(&self.pool.get()?)?
            .iter()
            .map(
                |&FriendRelation {
                     lesser_id: other_lesser_id,
                     greater_id: other_greater_id,
                     ..
                 }| {
                    if other_lesser_id == user {
                        other_greater_id
                    } else {
                        other_lesser_id
                    }
                },
            )
            .filter_map(|cur_friend| {
                Some(
                    registered_users
                        .filter(id.eq(cur_friend))
                        .first::<RegisteredUser>(&self.pool.get().ok()?)
                        .ok()?
                        .username,
                )
            })
            .collect();
        Ok(friends)
    }

    pub fn are_friends(&self, user: i32, friend_id: i32) -> Result<bool, TimeError> {
        use crate::schema::friend_relations::dsl::*;
        let (lesser, greater) = if user < friend_id {
            (user, friend_id)
        } else {
            (friend_id, user)
        };
        Ok(friend_relations
            .filter(lesser_id.eq(lesser).and(greater_id.eq(greater)))
            .first::<FriendRelation>(&self.pool.get()?)
            .optional()?
            .is_some())
    }

    pub fn remove_friend(&self, user: i32, friend_id: i32) -> Result<bool, TimeError> {
        use crate::schema::friend_relations::dsl::*;
        let (lesser, greater) = if user < friend_id {
            (user, friend_id)
        } else {
            (friend_id, user)
        };
        Ok(diesel::delete(friend_relations)
            .filter(lesser_id.eq(lesser).and(greater_id.eq(greater)))
            .execute(&self.pool.get()?)?
            != 0)
    }

    pub fn regenerate_friend_code(&self, userid: i32) -> Result<String, TimeError> {
        use crate::schema::registered_users::dsl::*;
        let code = crate::utils::generate_friend_code();
        diesel::update(crate::schema::registered_users::table)
            .filter(id.eq(userid))
            .set(friend_code.eq(&code))
            .execute(&self.pool.get()?)?;
        Ok(code)
    }

    pub fn delete_activity(&self, userid: i32, activity: i32) -> Result<bool, TimeError> {
        use crate::schema::coding_activities::dsl::*;
        let res = diesel::delete(crate::schema::coding_activities::table)
            .filter(id.eq(activity))
            .filter(user_id.eq(userid))
            .execute(&self.pool.get()?)?;
        Ok(res != 0)
    }
}
