from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, render_template
from peewee import (
    AutoField,
    CharField,
    Check,
    DateTimeField,
    ForeignKeyField,
    IntegerField,
    Model,
    SqliteDatabase,
)


BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
DATABASE_PATH = INSTANCE_DIR / "photo_share.db"
JAPAN_TIME_ZONE = timezone(timedelta(hours=9))

INSTANCE_DIR.mkdir(exist_ok=True)

database = SqliteDatabase(
    str(DATABASE_PATH),
    pragmas={"foreign_keys": 1},
)


def japan_now() -> datetime:
    """Return the current Japan time in the DB's timezone-naive format."""
    return datetime.now(JAPAN_TIME_ZONE).replace(tzinfo=None)


class BaseModel(Model):
    class Meta:
        database = database


class User(BaseModel):
    id = AutoField()
    display_name = CharField(max_length=50)
    email = CharField(max_length=254, unique=True)
    password_hash = CharField(max_length=255)
    created_at = DateTimeField(default=japan_now)

    class Meta:
        table_name = "users"


class Post(BaseModel):
    id = AutoField()
    user = ForeignKeyField(User, backref="posts", on_delete="RESTRICT")
    image_path = CharField(max_length=255, unique=True)
    image_mime_type = CharField(
        max_length=20,
        constraints=[Check("image_mime_type IN " "('image/jpeg', 'image/png', 'image/webp')")],
    )
    image_size = IntegerField(constraints=[Check("image_size BETWEEN 1 AND 10485760")])
    image_width = IntegerField(constraints=[Check("image_width >= 1")])
    image_height = IntegerField(constraints=[Check("image_height >= 1")])
    caption = CharField(
        max_length=200,
        constraints=[Check("length(trim(caption)) BETWEEN 1 AND 200")],
    )
    created_at = DateTimeField(default=japan_now, index=True)
    updated_at = DateTimeField(default=japan_now)

    class Meta:
        table_name = "posts"


app = Flask(__name__)


def initialize_database() -> None:
    database.connect(reuse_if_open=True)
    database.create_tables([User, Post], safe=True)
    database.close()


@app.before_request
def open_database_connection() -> None:
    if database.is_closed():
        database.connect()


@app.teardown_request
def close_database_connection(_exception: BaseException | None) -> None:
    if not database.is_closed():
        database.close()


@app.get("/")
def post_list():
    return render_template("posts/index.html")


initialize_database()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
    # app.run()
