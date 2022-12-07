from tortoise import Model, fields
from tortoise.contrib.pydantic import pydantic_model_creator
from passlib.hash import bcrypt


class User(Model):
    id = fields.IntField(pk=True, index=True, unique=True)
    username = fields.CharField(max_length=100)
    password = fields.CharField(max_length=100)
    first_name = fields.CharField(max_length=100)
    last_name = fields.CharField(max_length=100)
    email = fields.CharField(max_length=100)
    dob = fields.DatetimeField(auto_now_add=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now_add=True)
    is_verified = fields.BooleanField(default=False)

    def verify_password(self, password):
        return bcrypt.verify(password, self.password)


class Profile(Model):
    id = fields.IntField(pk=True, index=True, unique=True)
    user_id = fields.ForeignKeyField(
        'models.User', relative_name='user_profile')
    bio = fields.TextField()
    profile_picture = fields.CharField(
        max_length=100, null=False, default='default.jpg')
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)


# sanitized user model
user_pydantic = pydantic_model_creator(
    User, name="User", exclude=('is_verified', 'updated_at', 'created_at'))
user_pydanticIn = pydantic_model_creator(
    User, name="UserIn", exclude_readonly=True, exclude=('is_verified', 'updated_at', 'created_at'))
user_pydanticOut = pydantic_model_creator(
    User, name='UserOut', exclude=('password',))
# login
user_pydanticLogin = pydantic_model_creator(
    User, name='UserLogin', exclude=('is_verified', 'updated_at', 'created_at', 'first_name', 'last_name', 'dob', 'email', 'id'))

# sanitized Profile
profile_pydantic = pydantic_model_creator(
    Profile, name="Profile", exclude=('updated_at', 'created_at'))
profile_pydanticIn = pydantic_model_creator(
    Profile, name="ProfileIn", exclude_readonly=True, exclude=('updated_at', 'created_at'))
profile_pydanticOut = pydantic_model_creator(Profile, name='ProfileOut')
