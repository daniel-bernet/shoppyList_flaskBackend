# DataModel Implementation Project Documentation

## Projektbeschreibung

The following Text provides the technical documentation for the DataModel Implementation project, which involves a Flask API designed to support CRUD operations for a PostgreSQL database. The API serves a Flutter application that interacts with the database through HTTPS requests, facilitated by an Nginx proxy. The entire system is [dockerized](https://hub.docker.com/repository/docker/maknis3/flask-api/general) and hosted on [Unraid OS](https://unraid.net/).

## Dokumentation

### ER-Diagramm

![ER Diagram](/documentation/DB_ERD.png)

### Database Tables Description

#### User Table (`account`)

| Field         | Data Type          | Description                            |
| ------------- | ------------------ | -------------------------------------- |
| id            | UUID (Primary Key) | Unique identifier for the user         |
| username      | String (64)        | Username of the user                   |
| email         | String (120)       | Email address of the user              |
| password_hash | String (512)       | Hashed password of the user            |
| registered_on | DateTime           | Timestamp when the user was registered |
| last_login    | DateTime           | Timestamp of the user's last login     |

#### Shopping List Table (`shopping_list`)

| Field      | Data Type          | Description                                       |
| ---------- | ------------------ | ------------------------------------------------- |
| id         | UUID (Primary Key) | Unique identifier for the shopping list           |
| title      | String (120)       | Title of the shopping list                        |
| owner_id   | UUID (Foreign Key) | Identifier of the user who owns the shopping list |
| created_at | DateTime           | Timestamp when the shopping list was created      |
| updated_at | DateTime           | Timestamp when the shopping list was last updated |

#### Product Table (`product`)

| Field               | Data Type          | Description                                            |
| ------------------- | ------------------ | ------------------------------------------------------ |
| id                  | UUID (Primary Key) | Unique identifier for the product                      |
| quantity            | Integer            | Quantity of the product                                |
| unit_of_measurement | String (120)       | Unit of measurement for the product quantity           |
| name                | String (120)       | Name of the product                                    |
| creator_id          | UUID (Foreign Key) | Identifier of the user who created the product         |
| shopping_list_id    | UUID (Foreign Key) | Identifier of the shopping list the product belongs to |
| created_at          | DateTime           | Timestamp when the product was created                 |
| updated_at          | DateTime           | Timestamp when the product was last updated            |

#### Shopping List Collaborators (Join Table)

| Field            | Data Type          | Description                          |
| ---------------- | ------------------ | ------------------------------------ |
| shopping_list_id | UUID (Foreign Key) | Identifier of the shopping list      |
| account_id       | UUID (Foreign Key) | Identifier of the collaborating user |

### Source Code

- **No Redundancy:** The code is structured to avoid redundancy and maintain modularity.
- **Parameterized SQL:** SQL queries use parameters instead of hardcoding values to enhance security and flexibility.
- **Separation of Concerns:** Clear separation between SQL logic and application logic.
- **Exchangability:** The API is designed to be independent of SQL-dialect and database choice.
- **Error Handling:** Comprehensive error handling to manage and respond to exceptions gracefully.

### Applikation

- **User Input:** Describe how user input is captured and processed, e.g., via CLI or other interfaces.
- **Normalization:** The database tables are normalized to at least the third normal form.
- **CRUD Application:** The API supports Create, Read, Update, and Delete operations.
- **Database Script:** Include a script or instructions for initializing the database tables.
- **Content Search:** Functionality to search for content within the database.
- **Input Validation:** Ensure that data types are respected, e.g., no text in integer fields.
- **User Feedback:** Provide examples of user feedback for various operations, e.g., validation messages.
- **Error Handling:** Detail the error-handling mechanisms, including prompts for user re-entry in case of errors.

### Component-Diagram

![Component Diagram](/documentation/flask-api_component_diagram.png)

## API Code Overview

### /app.py

This script initializes and runs the Flask application.

Host and Port: The application listens on all network interfaces at port 5000.
SSL Context: The application uses an ad-hoc SSL context for secure connections.

### Dockerfile

Describes the Docker container setup, including the base Python image, dependencies, and exposed port.

### /app/init.py

Initializes the Flask application, SQLAlchemy, JWTManager, and Limiter. Configures the connection to the PostgreSQL database and sets up various security and performance-related settings.

### Models (/app/models.py)

Defines the SQLAlchemy models for User, ShoppingList, and Product, including their relationships and constraints.

### Routes (/app/routes.py)

Defines API endpoints for http requests, including user registration, login, token validation, password change, username edit, as CRUD operations for user management, products and shopping lists.
