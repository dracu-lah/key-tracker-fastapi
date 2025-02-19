from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from enum import Enum
from datetime import datetime
import sqlite3
import jwt
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
import re

# JWT configuration
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours

app = FastAPI(title="Key Management API")

security = HTTPBearer()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Connect to SQLite database
def get_db():
    conn = sqlite3.connect("database.sqlite")
    conn.row_factory = sqlite3.Row
    return conn


# Initialize database
def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Create auth_users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Create employees table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Create keys table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        current_holder INTEGER,
        status TEXT DEFAULT 'active',
        FOREIGN KEY(current_holder) REFERENCES employees(id)
    )
    """)

    # Create logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS key_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_id INTEGER,
        from_employee INTEGER,
        to_employee INTEGER,
        action TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(key_id) REFERENCES keys(id),
        FOREIGN KEY(from_employee) REFERENCES employees(id),
        FOREIGN KEY(to_employee) REFERENCES employees(id)
    )
    """)

    # Check if default admin user exists
    cursor.execute("SELECT COUNT(*) as count FROM auth_users WHERE username = 'admin'")
    if cursor.fetchone()["count"] == 0:
        # Create default admin user
        cursor.execute(
            "INSERT INTO auth_users (username, email, password) VALUES (?, ?, ?)",
            ["admin", "admin@udyata.com", "admin"],
        )

    # Check if keys exist
    cursor.execute("SELECT COUNT(*) as count FROM keys")
    if cursor.fetchone()["count"] == 0:
        # Initialize 4 keys
        for i in range(1, 5):
            cursor.execute(
                "INSERT INTO keys (name, description, status) VALUES (?, ?, 'active')",
                [f"Key {i}", f"Description for Key {i}"],
            )

    conn.commit()
    conn.close()


# Initialize database on startup
init_db()


# Auth functions
def create_access_token(data: dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
        return username
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token or expired token",
        )


# Pydantic Models
class Token(BaseModel):
    access_token: str
    token_type: str


class LoginCredentials(BaseModel):
    username: str
    password: str


class AuthUserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class AuthUser(BaseModel):
    id: int
    username: str
    email: EmailStr
    created_at: datetime

    class Config:
        orm_mode = True


class EmployeeStatus(str, Enum):
    ACTIVE = "active"
    LEFT = "left"
    DELETED = "deleted"


class KeyStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"


class LogAction(str, Enum):
    TRANSFER = "transfer"
    ASSIGN = "assign"
    UNASSIGN = "unassign"
    CREATE = "create"
    REMOVE = "remove"


class EmployeeBase(BaseModel):
    name: str
    email: Optional[EmailStr] = None


class EmployeeCreate(EmployeeBase):
    pass


class Employee(EmployeeBase):
    id: int
    status: EmployeeStatus
    created_at: datetime

    class Config:
        orm_mode = True


class KeyBase(BaseModel):
    name: str
    description: Optional[str] = None


class KeyCreate(KeyBase):
    pass


class Key(KeyBase):
    id: int
    current_holder: Optional[int] = None
    status: KeyStatus
    holder_name: Optional[str] = None

    class Config:
        orm_mode = True


class KeyAssign(BaseModel):
    employee_id: Optional[int] = None


class Log(BaseModel):
    id: int
    key_id: int
    key_name: str
    from_employee: Optional[str] = None
    to_employee: Optional[str] = None
    action: LogAction
    timestamp: datetime

    class Config:
        orm_mode = True


# Helper functions
def validate_email(email):
    return re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email) is not None


def ensure_key_not_assigned(conn, key_id):
    cursor = conn.cursor()
    cursor.execute("SELECT current_holder FROM keys WHERE id = ?", [key_id])
    key = cursor.fetchone()
    if key and key["current_holder"] is not None:
        return False
    return True


# API Routes - Authentication
@app.post("/api/login", response_model=Token, tags=["Authentication"])
def login(credentials: LoginCredentials):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM auth_users WHERE username = ?", [credentials.username]
    )
    user = cursor.fetchone()
    conn.close()

    if not user or user["password"] != credentials.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    access_token = create_access_token(data={"sub": credentials.username})
    return {"access_token": access_token, "token_type": "bearer"}


# Employees Routes
@app.get("/api/employees", response_model=List[Employee], tags=["Employees"])
def get_employees(_: str = Depends(verify_token)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM employees WHERE status != 'deleted' ORDER BY name")
    employees = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return employees


@app.post(
    "/api/employees",
    response_model=Employee,
    status_code=status.HTTP_201_CREATED,
    tags=["Employees"],
)
def create_employee(employee: EmployeeCreate, _: str = Depends(verify_token)):
    if employee.email and not validate_email(employee.email):
        raise HTTPException(status_code=400, detail="Invalid email format")

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO employees (name, email) VALUES (?, ?)",
            [employee.name, employee.email],
        )
        employee_id = cursor.lastrowid
        conn.commit()

        cursor.execute("SELECT * FROM employees WHERE id = ?", [employee_id])
        new_employee = dict(cursor.fetchone())
        conn.close()
        return new_employee
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Email already exists")
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))


@app.post(
    "/api/employees/{employee_id}/mark-left",
    response_model=Employee,
    tags=["Employees"],
)
def mark_employee_as_left(employee_id: int, _: str = Depends(verify_token)):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM keys WHERE current_holder = ?", [employee_id])
    keys = cursor.fetchall()
    if keys:
        conn.close()
        raise HTTPException(status_code=400, detail="Employee still has assigned keys")

    cursor.execute("UPDATE employees SET status = 'left' WHERE id = ?", [employee_id])
    conn.commit()

    cursor.execute("SELECT * FROM employees WHERE id = ?", [employee_id])
    updated_employee = dict(cursor.fetchone())
    conn.close()
    return updated_employee


@app.post(
    "/api/employees/{employee_id}/reactivate",
    response_model=Employee,
    tags=["Employees"],
)
def reactivate_employee(employee_id: int, _: str = Depends(verify_token)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE employees SET status = 'active' WHERE id = ?", [employee_id])
    conn.commit()

    cursor.execute("SELECT * FROM employees WHERE id = ?", [employee_id])
    updated_employee = dict(cursor.fetchone())
    conn.close()
    return updated_employee


@app.delete(
    "/api/employees/{employee_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Employees"],
)
def delete_employee(employee_id: int, _: str = Depends(verify_token)):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM keys WHERE current_holder = ?", [employee_id])
    keys = cursor.fetchall()
    if keys:
        conn.close()
        raise HTTPException(
            status_code=400, detail="Cannot delete employee with assigned keys"
        )

    cursor.execute(
        "UPDATE employees SET status = 'deleted' WHERE id = ?", [employee_id]
    )
    conn.commit()
    conn.close()
    return None


# Keys Routes
@app.get("/api/keys", response_model=List[Key], tags=["Keys"])
def get_keys(_: str = Depends(verify_token)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT k.*, e.name as holder_name
        FROM keys k
        LEFT JOIN employees e ON k.current_holder = e.id AND e.status != 'deleted'
        ORDER BY k.status, k.name
    """)
    keys = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return keys


@app.post(
    "/api/keys", response_model=Key, status_code=status.HTTP_201_CREATED, tags=["Keys"]
)
def create_key(key: KeyCreate, _: str = Depends(verify_token)):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO keys (name, description, status) VALUES (?, ?, 'active')",
            [key.name, key.description],
        )
        key_id = cursor.lastrowid

        cursor.execute(
            "INSERT INTO key_logs (key_id, action) VALUES (?, 'create')", [key_id]
        )
        conn.commit()

        cursor.execute(
            """
            SELECT k.*, e.name as holder_name
            FROM keys k
            LEFT JOIN employees e ON k.current_holder = e.id
            WHERE k.id = ?
        """,
            [key_id],
        )
        new_key = dict(cursor.fetchone())
        conn.close()
        return new_key
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/keys/{key_id}/toggle-status", response_model=Key, tags=["Keys"])
def toggle_key_status(key_id: int, _: str = Depends(verify_token)):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT status, current_holder FROM keys WHERE id = ?", [key_id])
    key = cursor.fetchone()
    if not key:
        conn.close()
        raise HTTPException(status_code=404, detail="Key not found")

    new_status = "inactive" if key["status"] == "active" else "active"

    if new_status == "inactive" and key["current_holder"] is not None:
        cursor.execute(
            "UPDATE keys SET status = ?, current_holder = NULL WHERE id = ?",
            [new_status, key_id],
        )
        cursor.execute(
            "INSERT INTO key_logs (key_id, from_employee, action) VALUES (?, ?, 'unassign')",
            [key_id, key["current_holder"]],
        )
    else:
        cursor.execute("UPDATE keys SET status = ? WHERE id = ?", [new_status, key_id])

    conn.commit()

    cursor.execute(
        """
        SELECT k.*, e.name as holder_name
        FROM keys k
        LEFT JOIN employees e ON k.current_holder = e.id AND e.status != 'deleted'
        WHERE k.id = ?
    """,
        [key_id],
    )
    updated_key = dict(cursor.fetchone())
    conn.close()
    return updated_key


@app.delete("/api/keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Keys"])
def delete_key(key_id: int, _: str = Depends(verify_token)):
    conn = get_db()
    cursor = conn.cursor()

    if not ensure_key_not_assigned(conn, key_id):
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="Cannot remove key while it's assigned to an employee",
        )

    cursor.execute("DELETE FROM keys WHERE id = ?", [key_id])
    cursor.execute(
        "INSERT INTO key_logs (key_id, action) VALUES (?, 'remove')", [key_id]
    )

    conn.commit()
    conn.close()
    return None


@app.post("/api/keys/{key_id}/assign", response_model=Key, tags=["Keys"])
def assign_key(key_id: int, assignment: KeyAssign, _: str = Depends(verify_token)):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT current_holder FROM keys WHERE id = ?", [key_id])
    key = cursor.fetchone()
    if not key:
        conn.close()
        raise HTTPException(status_code=404, detail="Key not found")

    from_employee = key["current_holder"]
    to_employee = assignment.employee_id

    if from_employee is None and to_employee is not None:
        action = "assign"
    elif from_employee is not None and to_employee is None:
        action = "unassign"
    else:
        action = "transfer"

    cursor.execute(
        "UPDATE keys SET current_holder = ? WHERE id = ?", [to_employee, key_id]
    )
    cursor.execute(
        "INSERT INTO key_logs (key_id, from_employee, to_employee, action) VALUES (?, ?, ?, ?)",
        [key_id, from_employee, to_employee, action],
    )

    conn.commit()

    cursor.execute(
        """
        SELECT k.*, e.name as holder_name
        FROM keys k
        LEFT JOIN employees e ON k.current_holder = e.id AND e.status != 'deleted'
        WHERE k.id = ?
    """,
        [key_id],
    )
    updated_key = dict(cursor.fetchone())
    conn.close()
    return updated_key


@app.get("/api/logs", response_model=List[Log], tags=["Logs"])
def get_logs(_: str = Depends(verify_token)):
    conn = get_db()
    cursor = conn.cursor()

    query = """
        SELECT
            kl.*,
            k.name as key_name,
            e_from.name as from_employee,
            e_to.name as to_employee
        FROM key_logs kl
        LEFT JOIN keys k ON kl.key_id = k.id
        LEFT JOIN employees e_from ON kl.from_employee = e_from.id
        LEFT JOIN employees e_to ON kl.to_employee = e_to.id
        ORDER BY kl.timestamp DESC
    """

    cursor.execute(query)
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logs


# User Management for Administrators
@app.get("/api/auth-users", response_model=List[AuthUser], tags=["Admin Users"])
def get_auth_users(_: str = Depends(verify_token)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, email, created_at FROM auth_users ORDER BY username"
    )
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return users


@app.post(
    "/api/auth-users",
    response_model=AuthUser,
    status_code=status.HTTP_201_CREATED,
    tags=["Admin Users"],
)
def create_auth_user(user: AuthUserCreate, _: str = Depends(verify_token)):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO auth_users (username, email, password) VALUES (?, ?, ?)",
            [user.username, user.email, user.password],
        )
        user_id = cursor.lastrowid
        conn.commit()

        cursor.execute(
            "SELECT id, username, email, created_at FROM auth_users WHERE id = ?",
            [user_id],
        )
        new_user = dict(cursor.fetchone())
        conn.close()
        return new_user
    except sqlite3.IntegrityError as e:
        conn.close()
        if "username" in str(e):
            raise HTTPException(status_code=400, detail="Username already exists")
        else:
            raise HTTPException(status_code=400, detail="Email already exists")
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))


# Custom OpenAPI schema
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Key Management API",
        version="1.0.0",
        description="API for managing keys and their assignments to employees",
        routes=app.routes,
    )

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
