import os
import uuid
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cachelib.file import FileSystemCache
from dotenv import load_dotenv
from flask import (
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask import Flask
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_session import Session
from flask_wtf import CSRFProtect, FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from PIL import Image, UnidentifiedImageError
from peewee import (
    AutoField,
    CharField,
    Check,
    DateTimeField,
    ForeignKeyField,
    IntegerField,
    Model,
    SqliteDatabase,
    IntegrityError,
)
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from wtforms import HiddenField, PasswordField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length


BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
DATABASE_PATH = INSTANCE_DIR / "photo_share.db"
SESSION_DIR = INSTANCE_DIR / "sessions"
POST_UPLOAD_DIR = BASE_DIR / "uploads" / "posts"
JAPAN_TIME_ZONE = timezone(timedelta(hours=9))
MAX_IMAGE_BYTES = 10 * 1024 * 1024
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
IMAGE_FORMATS = {
    "PNG": ("png", "image/png"),
    "JPEG": ("jpg", "image/jpeg"),
    "GIF": ("gif", "image/gif"),
}

INSTANCE_DIR.mkdir(exist_ok=True)
SESSION_DIR.mkdir(exist_ok=True)
POST_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
load_dotenv(BASE_DIR / ".env")

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


class User(UserMixin, BaseModel):
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
        constraints=[Check("image_mime_type IN " "('image/jpeg', 'image/png', 'image/gif')")],
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


class RegisterForm(FlaskForm):
    display_name = StringField(
        "表示名",
        validators=[DataRequired(), Length(max=50)],
    )
    email = StringField(
        "メールアドレス",
        validators=[DataRequired(), Email(), Length(max=254)],
    )
    password = PasswordField(
        "パスワード",
        validators=[DataRequired(), Length(min=8, max=128)],
    )
    password_confirmation = PasswordField(
        "確認用パスワード",
        validators=[
            DataRequired(),
            EqualTo("password", message="パスワードが一致しません。"),
        ],
    )
    submit = SubmitField("登録")


class LoginForm(FlaskForm):
    email = StringField(
        "メールアドレス",
        validators=[DataRequired(), Email(), Length(max=254)],
    )
    password = PasswordField(
        "パスワード",
        validators=[DataRequired(), Length(max=128)],
    )
    next_url = HiddenField()
    submit = SubmitField("ログイン")


class LogoutForm(FlaskForm):
    submit = SubmitField("ログアウト")


class PostCreateForm(FlaskForm):
    image = FileField(
        "写真",
        validators=[
            FileRequired(message="写真を選択してください。"),
            FileAllowed(
                ALLOWED_IMAGE_EXTENSIONS,
                message="png、jpg、jpeg、gif形式の画像を選択してください。",
            ),
        ],
    )
    caption = TextAreaField(
        "キャプション",
        validators=[
            DataRequired(message="キャプションを入力してください。"),
            Length(max=200, message="キャプションは200文字以内で入力してください。"),
        ],
    )
    submit = SubmitField("投稿する")


app = Flask(__name__)

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("環境変数SECRET_KEYを設定してください。")

app.config.update(
    SECRET_KEY=secret_key,
    SESSION_TYPE="cachelib",
    SESSION_CACHELIB=FileSystemCache(cache_dir=str(SESSION_DIR), threshold=500),
    SESSION_SERIALIZATION_FORMAT="json",
    SESSION_PERMANENT=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=MAX_IMAGE_BYTES + (512 * 1024),
)

Session(app)
CSRFProtect(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "この機能を利用するにはログインしてください。"
login_manager.login_message_category = "warning"
login_manager.init_app(app)


def initialize_database() -> None:
    database.connect(reuse_if_open=True)
    database.create_tables([User, Post], safe=True)
    database.close()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def is_safe_next_url(target: str | None) -> bool:
    if not target:
        return False

    parsed = urlsplit(target)
    return (
        not parsed.scheme
        and not parsed.netloc
        and target.startswith("/")
        and not target.startswith("//")
    )


def inspect_uploaded_image(image_file) -> tuple[str, str, int, int, int]:
    """Validate an uploaded image and return safe metadata."""
    original_extension = Path(image_file.filename or "").suffix.lower().lstrip(".")
    safe_name = secure_filename(f"upload.{original_extension}")
    extension = Path(safe_name).suffix.lower().lstrip(".")
    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError("png、jpg、jpeg、gif形式の画像を選択してください。")

    image_file.stream.seek(0, os.SEEK_END)
    image_size = image_file.stream.tell()
    image_file.stream.seek(0)
    if image_size < 1:
        raise ValueError("空のファイルは投稿できません。")
    if image_size > MAX_IMAGE_BYTES:
        raise ValueError("画像は10MB以下にしてください。")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(image_file.stream) as uploaded_image:
                image_format = uploaded_image.format
                uploaded_image.verify()

            image_file.stream.seek(0)
            with Image.open(image_file.stream) as uploaded_image:
                width, height = uploaded_image.size
    except (
        UnidentifiedImageError,
        OSError,
        SyntaxError,
        ValueError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ) as error:
        raise ValueError("有効な画像ファイルを選択してください。") from error
    finally:
        image_file.stream.seek(0)

    if image_format not in IMAGE_FORMATS:
        raise ValueError("png、jpg、jpeg、gif形式の画像を選択してください。")

    safe_extension, mime_type = IMAGE_FORMATS[image_format]
    matching_extensions = {safe_extension}
    if image_format == "JPEG":
        matching_extensions.add("jpeg")
    if extension not in matching_extensions:
        raise ValueError("ファイルの拡張子と画像形式が一致していません。")
    if width < 1 or height < 1:
        raise ValueError("画像の幅と高さを確認してください。")

    return safe_extension, mime_type, image_size, width, height


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    try:
        return User.get_by_id(int(user_id))
    except (ValueError, User.DoesNotExist):
        return None


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
    posts = Post.select(Post, User).join(User).order_by(Post.created_at.desc())
    return render_template(
        "posts/index.html",
        posts=posts,
        logout_form=LogoutForm(),
    )


@app.route("/posts/new", methods=["GET", "POST"])
@login_required
def post_create():
    form = PostCreateForm()
    if form.validate_on_submit():
        caption = form.caption.data.strip()
        if not caption:
            form.caption.errors.append("キャプションを入力してください。")
            return render_template(
                "posts/new.html",
                form=form,
                logout_form=LogoutForm(),
            )

        try:
            extension, mime_type, image_size, width, height = inspect_uploaded_image(
                form.image.data
            )
        except ValueError as error:
            form.image.errors.append(str(error))
        else:
            saved_name = f"{uuid.uuid4().hex}.{extension}"
            relative_path = f"posts/{saved_name}"
            destination = POST_UPLOAD_DIR / saved_name
            form.image.data.save(destination)

            try:
                Post.create(
                    user=current_user.id,
                    image_path=relative_path,
                    image_mime_type=mime_type,
                    image_size=image_size,
                    image_width=width,
                    image_height=height,
                    caption=caption,
                )
            except Exception:
                destination.unlink(missing_ok=True)
                app.logger.exception("投稿のデータベース登録に失敗しました。")
                flash("投稿を保存できませんでした。時間をおいて再度お試しください。", "error")
            else:
                flash("写真を投稿しました。", "success")
                return redirect(url_for("post_list"))

    return render_template(
        "posts/new.html",
        form=form,
        logout_form=LogoutForm(),
    )


@app.get("/uploads/posts/<filename>")
def uploaded_post_image(filename: str):
    return send_from_directory(POST_UPLOAD_DIR, filename)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("post_list"))

    form = RegisterForm()
    if form.validate_on_submit():
        display_name = form.display_name.data.strip()
        email = normalize_email(form.email.data)

        if User.select().where(User.email == email).exists():
            form.email.errors.append("このメールアドレスはすでに登録されています。")
        else:
            try:
                User.create(
                    display_name=display_name,
                    email=email,
                    password_hash=generate_password_hash(form.password.data),
                )
            except IntegrityError:
                form.email.errors.append(
                    "このメールアドレスはすでに登録されています。"
                )
            else:
                flash("ユーザー登録が完了しました。ログインしてください。", "success")
                return redirect(url_for("login"))

    return render_template("auth/register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("post_list"))

    form = LoginForm()
    if request.method == "GET":
        form.next_url.data = request.args.get("next", "")

    if form.validate_on_submit():
        email = normalize_email(form.email.data)
        user = User.get_or_none(User.email == email)

        if user is not None and check_password_hash(
            user.password_hash,
            form.password.data,
        ):
            app.session_interface.regenerate(session)
            login_user(user)
            flash("ログインしました。", "success")

            if is_safe_next_url(form.next_url.data):
                return redirect(form.next_url.data)
            return redirect(url_for("post_list"))

        form.password.errors.append(
            "メールアドレスまたはパスワードが正しくありません。"
        )

    return render_template("auth/login.html", form=form)


@app.post("/logout")
@login_required
def logout():
    form = LogoutForm()
    if not form.validate_on_submit():
        return "不正なリクエストです。", 400

    logout_user()
    flash("ログアウトしました。", "success")
    return redirect(url_for("post_list"))


@app.errorhandler(RequestEntityTooLarge)
def handle_request_too_large(_error):
    flash("画像は10MB以下にしてください。", "error")
    if current_user.is_authenticated:
        return redirect(url_for("post_create"))
    return redirect(url_for("login"))


initialize_database()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
    # app.run()
