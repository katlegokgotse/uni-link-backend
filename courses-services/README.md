# UniLink Backend Service

## Overview

UniLink is a backend service designed for managing university applications. It allows students to register, apply to universities, and track their application status. The system also supports authentication and authorization using JWT.

## Features

- User authentication (registration & login)
- Student management (add and retrieve students)
- University management (add universities)
- Application processing (students apply to universities)
- Secure API endpoints with JWT authentication

## Tech Stack

- **Backend:** Flask
- **Database:** PostgreSQL
- **Authentication:** Flask-JWT-Extended
- **ORM:** SQLAlchemy
- **Encryption:** Flask-Bcrypt
- **Schema Validation:** Marshmallow

## Installation & Setup

### Prerequisites

Ensure you have the following installed:

- Python 3.x
- PostgreSQL
- pip (Python package manager)

### Setup Steps

1. **Clone the repository:**
   ```sh
   git clone <repository-url>
   cd UniLink-Backend
   ```
2. **Create and activate a virtual environment:**
   ```sh
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```
3. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
4. **Set environment variables:**
   ```sh
   export FLASK_APP=app.py
   export FLASK_ENV=development
   ```
5. **Configure Database:**
   Update `SQLALCHEMY_DATABASE_URI` in `app.py` to match your PostgreSQL database.
6. **Run the application:**
   ```sh
   python app.py
   ```

## API Endpoints

### Authentication

| Method | Endpoint    | Description             |
| ------ | ----------- | ----------------------- |
| POST   | `/register` | Register a user         |
| POST   | `/login`    | Login and get JWT token |

### Student Management

| Method | Endpoint             | Description                           |
| ------ | -------------------- | ------------------------------------- |
| POST   | `/students/register` | Register a new student (JWT required) |
| GET    | `/students`          | Get all students (JWT required)       |

### University Management

| Method | Endpoint        | Description      |
| ------ | --------------- | ---------------- |
| POST   | `/universities` | Add a university |

### Applications

| Method | Endpoint                              | Description           |
| ------ | ------------------------------------- | --------------------- |
| POST   | `/apply/<student_id>/<university_id>` | Apply to a university |

## Environment Variables

Ensure the following environment variables are set:

- `SQLALCHEMY_DATABASE_URI` - Your PostgreSQL connection string
- `JWT_SECRET_KEY` - Secret key for JWT authentication
- `FLASK_ENV` - Set to `development` for debugging mode

## Deployment

For deploying to a cloud service like Render, ensure:

- The database connection is updated for production
- JWT secret key is stored securely
- Debug mode is disabled (`FLASK_ENV=production`)

## License

This project is licensed under the MIT License.

MIT Liscence
