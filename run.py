from flask import Blueprint, jsonify, request
from flask.views import MethodView

from app import db
from models import Subject, User

subject_blueprint = Blueprint('subject_blueprint', __name__, url_prefix='/subjects')


class SubjectAPI(MethodView):
    def get(self, subject_id):
        if not subject_id or not subject_id.isdigit():
            return jsonify({'status': 'fail', 'message': 'Invalid subject_id provided!'}), 400

        subject = Subject.query.filter_by(id=subject_id).first()
        if subject:
            return jsonify({'status': 'success', 'data': subject.to_dict()}), 200
        return jsonify({'status': 'fail', 'message': 'Subject not found!'}), 404

    def post(self):
        post_data = request.get_json()
        subject = Subject(
            name=post_data['name'],
            description=post_data['description'],
            teacher_id=post_data['teacher_id']
        )
        db.session.add(subject)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Subject created!'}), 201

    def put(self):
        put_data = request.get_json()
        if not put_data.get('subject_id'):
            return jsonify({'status': 'fail', 'message': 'Missed required field subject_id!'}), 400
        if not put_data.get('student_ids'):
            return jsonify({'status': 'fail', 'message': 'Missed required field student_ids!'}), 400
        if not all(isinstance(i, int) for i in put_data['student_ids']):
            return jsonify({'status': 'fail', 'message': 'student_ids must be list of integers!'}), 400
        subject = Subject.query.filter_by(id=put_data['subject_id']).first()
        if not subject:
            return jsonify({'status': 'fail', 'message': 'Subject with this subject_id not found!'}), 400
        students = User.query.filter(User.id.in_(put_data['student_ids'])).all()
        if len(students) != len(put_data['student_ids']):
            return jsonify({'status': 'fail', 'message': 'Not all student_ids is true!'}), 400
        subject.students = students
        db.session.add(subject)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Subject changed!'}), 200


subject_view = SubjectAPI.as_view('subject_api')

subject_blueprint.add_url_rule('/<string:subject_id>', view_func=subject_view, methods=['GET'])
subject_blueprint.add_url_rule('/', view_func=subject_view, methods=['POST', 'PUT'])
