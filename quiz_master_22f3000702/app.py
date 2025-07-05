from datetime import datetime

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'e49b7a8d7c0a4aebf18c9a8c3f8a6d77d21b4a5a0f3c8e47c76d9d0e7e3a4b9f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz_master.db'
db = SQLAlchemy(app)

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect users to login page if not logged in

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)  # Hashed password
    full_name = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # "admin" or "user"
    qualification = db.Column(db.String(150), nullable=True)
    date = db.Column(db.Date, nullable=True)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    quizzes = db.relationship('Quiz', back_populates='subject', cascade="all, delete-orphan")
    description = db.Column(db.String(200), nullable=False)

class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    quizzes = db.relationship('Quiz', back_populates='chapter', cascade="all, delete-orphan")
    description = db.Column(db.String(200), nullable=False)


class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    date = db.Column(db.Date, nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id'), nullable=False)  # Ensure this line exists!
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)  # Ensure subject_id is also linked

    chapter = db.relationship('Chapter', back_populates='quizzes')  # Define relationship
    subject = db.relationship('Subject', back_populates='quizzes')  # Define relationship



class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    option_a = db.Column(db.String(200), nullable=False)
    option_b = db.Column(db.String(200), nullable=False)
    option_c = db.Column(db.String(200), nullable=False)
    option_d = db.Column(db.String(200), nullable=False)
    correct_option = db.Column(db.String(1), nullable=False)  # 'A', 'B', 'C', or 'D'
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)

class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='attempts')
    quiz = db.relationship('Quiz', backref='attempts')



# Initialize the database
with app.app_context():
    db.create_all()
    # Create an admin user if not exists
    if not User.query.filter_by(email="admin@quizmaster.com").first():
        new_admin = User(
            email="admin@quizmaster.com",
            password=generate_password_hash("admin123", method='pbkdf2:sha256'),
            full_name="Admin",
            role="admin"
        )
        db.session.add(new_admin)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home Route
@app.route('/')
def home():
    return render_template('index.html')

# Register Route (Only for Users)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        full_name = request.form['full_name']
        qualification = request.form['qualification']
        date_str = request.form['date']
        date = datetime.strptime(date_str, '%Y-%m-%d').date()


        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, password=hashed_password, full_name=full_name, role="user",qualification=qualification,date=date)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.role == "admin":
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid email or password!', 'danger')
    
    return render_template('login.html')

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Admin Dashboard (Only Admins)
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        return redirect(url_for('home'))

    search_query = request.args.get('search', '').strip()

    if search_query:
        quizzes = Quiz.query.join(Subject).filter(
            (Quiz.title.ilike(f"%{search_query}%")) | 
            (Subject.name.ilike(f"%{search_query}%"))
        ).all()
    else:
        quizzes = Quiz.query.all()

    subjects = Subject.query.all()
    return render_template('admin_dashboard.html', quizzes=quizzes, subjects=subjects, search_query=search_query)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.role != "user":
        return redirect(url_for('home'))

    search_query = request.args.get('search', '').strip()

    if search_query:
        quizzes = Quiz.query.join(Subject).filter(
            (Quiz.title.ilike(f"%{search_query}%")) | 
            (Subject.name.ilike(f"%{search_query}%"))
        ).all()
    else:
        quizzes = Quiz.query.all()

    attempts = QuizAttempt.query.filter_by(user_id=current_user.id).all()

    return render_template('user_dashboard.html', quizzes=quizzes, attempts=attempts, search_query=search_query)



@app.route('/admin/create_subject', methods=['GET', 'POST'])
@login_required
def create_subject():
    if current_user.role != "admin":
        return redirect(url_for('home'))

    if request.method == 'POST':
        subject_name = request.form.get('subject_name')
        description = request.form.get('description')

        if not subject_name:
            flash("Please enter a subject name!", "danger")
            return redirect(url_for('create_subject'))

        # Check if the subject already exists
        existing_subject = Subject.query.filter_by(name=subject_name).first()
        if existing_subject:
            flash("Subject already exists!", "warning")
            return redirect(url_for('create_subject'))

        # Create new subject
        new_subject = Subject(name=subject_name,description=description)
        db.session.add(new_subject)
        db.session.commit()
        flash("Subject created successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('create_subject.html')


@app.route('/admin/create_chapter', methods=['GET', 'POST'])
@login_required
def create_chapter():
    if current_user.role != "admin":
        return redirect(url_for('home'))

    subjects = Subject.query.all()  # Fetch all subjects for selection

    if request.method == 'POST':
        subject_id = request.form.get('subject_id')  # Get subject_id from form
        chapter_name = request.form.get('chapter_name')
        description = request.form.get('description')

        if not subject_id or not chapter_name:
            flash("Please fill in all fields!", "danger")
            return redirect(url_for('create_chapter'))

        # Create new chapter
        new_chapter = Chapter(name=chapter_name, description=description)

        db.session.add(new_chapter)
        db.session.commit()
        flash("Chapter created successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('create_chapter.html', subjects=subjects)

@app.route('/admin/create_quiz', methods=['GET', 'POST'])
@login_required
def create_quiz():
    if current_user.role != "admin":
        return redirect(url_for('home'))

    chapters = Chapter.query.all()  # Fetch all chapters
    subjects = Subject.query.all()  # Fetch all subjects

    if request.method == 'POST':
        title = request.form.get('title')
        date_str = request.form['date']  # Expecting 'YYYY-MM-DD'
        duration = request.form.get('duration')
        chapter_id = request.form.get('chapter_id')
        subject_id = request.form.get('subject_id')
        date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()

        if not chapter_id or not subject_id or not title:
            flash("Please fill in all fields!", "danger")
            return redirect(url_for('create_quiz'))

        new_quiz = Quiz(
            title=title, 
            date=date_obj,
            duration=duration, 
            chapter_id=int(chapter_id), 
            subject_id=int(subject_id)  # Added this line
        )

        db.session.add(new_quiz)
        db.session.commit()

        flash("Quiz created successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('create_quiz.html', chapters=chapters, subjects=subjects)


@app.route('/admin/delete_quiz/<int:quiz_id>', methods=['POST'])
@login_required
def delete_quiz(quiz_id):
    if current_user.role != "admin":
        return redirect(url_for('home'))

    quiz = Quiz.query.get_or_404(quiz_id)

    # Delete related quiz_attempt records first
    QuizAttempt.query.filter_by(quiz_id=quiz_id).delete()

    # Now delete the quiz
    db.session.delete(quiz)
    db.session.commit()
    
    flash("Quiz deleted successfully!", "success")
    return redirect(url_for('admin_dashboard'))


@app.route('/edit_quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def edit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()  # Fetch questions

    if request.method == 'POST':
        for question in questions:
            question.text = request.form.get(f'question_text_{question.id}')
            question.option_a = request.form.get(f'option_a_{question.id}')
            question.option_b = request.form.get(f'option_b_{question.id}')
            question.option_c = request.form.get(f'option_c_{question.id}')
            question.option_d = request.form.get(f'option_d_{question.id}')
            question.correct_option = request.form.get(f'correct_option_{question.id}')
        db.session.commit()
        flash('Quiz updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_quiz.html', quiz=quiz, questions=questions)



@app.route('/admin/add_question/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def add_question(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)  # Fetch quiz from database

    if request.method == 'POST':
        question_text = request.form['question_text']
        option_a = request.form['option_a']
        option_b = request.form['option_b']
        option_c = request.form['option_c']
        option_d = request.form['option_d']
        correct_answer = request.form['correct_answer']

        new_question = Question(quiz_id=quiz.id, text=question_text, option_a=option_a, option_b=option_b,
                                option_c=option_c, option_d=option_d, correct_option=correct_answer)
        db.session.add(new_question)
        db.session.commit()
        flash('Question added successfully!', 'success')
        return redirect(url_for('add_question', quiz_id=quiz.id))

    return render_template('add_question.html', quiz=quiz)

@app.route('/quizzes')
@login_required
def quizzes():
    quizzes = Quiz.query.all()
    return render_template('quizzes.html', quizzes=quizzes)

@app.route('/attempt_quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def attempt_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()

    if request.method == 'POST':
        score = 0
        for question in questions:
            selected_answer = request.form.get(f'question_{question.id}')
            if selected_answer == question.correct_option:
                score += 1
        attempt = QuizAttempt(user_id=current_user.id, quiz_id=quiz_id, score=score)
        db.session.add(attempt)
        db.session.commit()

        flash(f'You scored {score}/{len(questions)}!', 'info')
        return redirect(url_for('user_dashboard'))

    return render_template('attempt_quiz.html', quiz=quiz, questions=questions)
@app.route('/admin/analytics')
@login_required
def admin_analytics():
    if current_user.role != "admin":
        return redirect(url_for('home'))

    # General Stats
    total_quizzes = Quiz.query.count()
    total_users = User.query.filter_by(role="user").count()
    total_attempts = QuizAttempt.query.count()

    # Fetch quiz attempts per quiz
    quiz_attempts = db.session.query(Quiz.title, db.func.count(QuizAttempt.id)) \
        .join(QuizAttempt, Quiz.id == QuizAttempt.quiz_id).group_by(Quiz.id).all()
    quiz_labels, quiz_data = zip(*quiz_attempts) if quiz_attempts else ([], [])

    # Users per quiz
    users_per_quiz = db.session.query(Quiz.title, db.func.count(QuizAttempt.user_id)) \
        .join(QuizAttempt, Quiz.id == QuizAttempt.quiz_id).group_by(Quiz.id).all()
    user_labels, user_data = zip(*users_per_quiz) if users_per_quiz else ([], [])

    # Ensure all variables are initialized
    if not user_labels:
        user_labels = []
    if not user_data:
        user_data = []

    return render_template(
        "admin_analytics.html",
        total_quizzes=total_quizzes,
        total_users=total_users,
        total_attempts=total_attempts,
        quiz_labels=quiz_labels,
        quiz_data=quiz_data,
        user_labels=user_labels,
        user_data=user_data
    )


@app.route('/user/analytics')
@login_required
def user_analytics():
    if current_user.role != "user":
        return redirect(url_for('home'))

    attempts = QuizAttempt.query.filter_by(user_id=current_user.id).all()
    total_attempts = len(attempts)
    avg_score = round(sum(a.score for a in attempts) / total_attempts, 2) if total_attempts > 0 else 0

    quiz_scores = [(a.quiz.title, a.score) for a in attempts]
    quiz_labels, quiz_data = zip(*quiz_scores) if quiz_scores else ([], [])

    print("Quiz Labels:", quiz_labels)  # Debugging step
    print("Quiz Data:", quiz_data)  # Debugging step

    return render_template(
        "user_analytics.html",
        total_attempts=total_attempts,
        avg_score=avg_score,
        quiz_labels=quiz_labels,
        quiz_data=quiz_data
    )




if __name__ == '__main__':
    app.run(debug=True)
