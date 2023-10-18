import traceback

import jwt
from email_validator import validate_email, EmailNotValidError
from flasgger import swag_from
from flask import Blueprint, request, jsonify
from flask.views import MethodView

from app import bcrypt, db, app
from config import Config
from mail import send_email, create_approve_url
from models import User, BlacklistToken, SubjectRating

auth_blueprint = Blueprint('auth', __name__, url_prefix='/auth')


class ApprovalAPI(MethodView):
    def get(self, approval_code):
        """Endpoint for approve user by approval code
            ---
            parameters:
              - name: approval_code
                in: path
                type: string
                required: true
            responses:
              200:
                description: User approved his account
              400:
                description: User already approved or bad code
            """
        try:
            payload = jwt.decode(approval_code, key=Config.SECRET_APPROVAL_KEY, algorithms=['HS256'])
        except (jwt.InvalidTokenError, jwt.ExpiredSignatureError):
            return jsonify({'status': 'fail', 'message': 'Invalid code. Please try again.'}), 400
        user = User.query.filter_by(id=payload['sub']).first()
        if user.mail_approved:
            return jsonify({'status': 'fail', 'message': 'This user has already approved mail!'}), 400
        user.mail_approved = True
        db.session.add(user)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Congratulations! You has approved your account!'}), 200


class RegisterAPI(MethodView):
    @swag_from()
    def post(self):
        post_data = request.get_json()

        email = post_data.get('email')
        password = post_data.get('password')

        if not email:
            return jsonify({'status': 'fail', 'message': 'Email is required!'}), 400

        if not password:
            return jsonify({'status': 'fail', 'message': 'Password is required!'}), 400

        user = User.query.filter_by(email=email).first()
        if user:
            return jsonify({'status': 'fail', 'message': 'User already exists. Please Log in.'}), 202

        try:
            validate_email(email, check_deliverability=False)
            user = User(email=email, password=post_data.get('password'))
            db.session.add(user)
            db.session.commit()
            send_email(email, 'Approve registration', f'Your link is {create_approve_url(user.id)}')
            return jsonify(
                {'status': 'success', 'message': 'Approve message sent to your email!'}), 201

        except EmailNotValidError as e:
            app.logger.error(e)
            return jsonify({'status': 'fail', 'message': 'Your email is not valid!'})

        except Exception as e:
            app.logger.error(e)
            return jsonify({'status': 'fail', 'message': 'Some error occurred. Please try again.'}), 401


class LoginAPI(MethodView):
    def post(self):
        post_data = request.get_json()

        email = post_data.get('email')
        password = post_data.get('password')

        if not email:
            return jsonify({'status': 'fail', 'message': 'Email is required!'}), 400

        if not password:
            return jsonify({'status': 'fail', 'message': 'Password is required!'}), 400

        try:
            user = User.query.filter_by(email=post_data.get('email')).first()

            if user and bcrypt.check_password_hash(user.password, post_data.get('password')):
                auth_token = user.encode_auth_token(user.id)
                return jsonify(
                    {'status': 'success', 'message': 'Successfully logged in.', 'auth_token': auth_token}), 200

            return jsonify({'status': 'fail', 'message': 'User does not exist.'}), 404

        except Exception as e:
            app.logger.error(traceback.format_exc())
            return jsonify({'status': 'fail', 'message': 'Try again'}), 500


class UserAPI(MethodView):
    def get(self):
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return jsonify({'status': 'fail', 'message': 'Provide a valid auth token.'}), 401

        try:
            auth_token = auth_header.split(" ")[1]
            resp = User.decode_auth_token(auth_token)

            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                return jsonify({
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                        'admin': user.admin,
                        'registered_on': user.registered_on
                    }
                }), 200

            return jsonify({'status': 'fail', 'message': resp}), 401

        except IndexError:
            return jsonify({'status': 'fail', 'message': 'Bearer token malformed.'}), 401


class LogoutAPI(MethodView):
    def post(self):
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return jsonify({'status': 'fail', 'message': 'Provide a valid auth token.'}), 403

        try:
            auth_token = auth_header.split(" ")[1]
            resp = User.decode_auth_token(auth_token)

            if not isinstance(resp, str):
                blacklist_token = BlacklistToken(token=auth_token)
                db.session.add(blacklist_token)
                db.session.commit()
                return jsonify({'status': 'success', 'message': 'Successfully logged out.'}), 200

            return jsonify({'status': 'fail', 'message': resp}), 401

        except IndexError:
            return jsonify({'status': 'fail', 'message': 'Bearer token malformed.'}), 401


class SubjectRatingAPI(MethodView):
    def post(self):
        post_data = request.get_json()
        subject_id = post_data.get('subject_id')
        rating = post_data.get('rating')

        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'status': 'fail', 'message': 'No auth token provided.'}), 401

        auth_token = auth_header.split(" ")[1]
        student_id = User.decode_auth_token(auth_token)

        if isinstance(student_id, str):
            return jsonify({'status': 'fail', 'message': student_id}), 401

        if not all([subject_id, rating]):
            return jsonify({'status': 'fail', 'message': 'Missing required parameters.'}), 400

        try:
            existing_rating = SubjectRating.query.filter_by(student_id=student_id, subject_id=subject_id).first()
            if existing_rating:
                return jsonify({'status': 'fail', 'message': 'You have already rated this subject.'}), 400

            new_rating = SubjectRating(student_id=student_id, subject_id=subject_id, rating=rating)
            db.session.add(new_rating)
            db.session.commit()

            return jsonify({'status': 'success', 'message': 'Rating added successfully!'}), 200

        except Exception as e:
            app.logger.error(traceback.format_exc())
            return jsonify({'status': 'fail', 'message': 'An error occurred. Please try again.'}), 500


registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
user_view = UserAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')
approval_view = ApprovalAPI.as_view('approval_api')
rating_view = SubjectRatingAPI.as_view('subject_rating_api')

auth_blueprint.add_url_rule('/register', view_func=registration_view, methods=['POST'])
auth_blueprint.add_url_rule('/login', view_func=login_view, methods=['POST'])
auth_blueprint.add_url_rule('/status', view_func=user_view, methods=['GET'])
auth_blueprint.add_url_rule('/logout', view_func=logout_view, methods=['POST'])
auth_blueprint.add_url_rule('/approval/<string:approval_code>', view_func=approval_view, methods=['GET'])
auth_blueprint.add_url_rule('/rate_subject', view_func=rating_view, methods=['POST'])
