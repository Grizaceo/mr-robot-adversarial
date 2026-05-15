"""psycopg2 with parameter binding — no string interpolation, no injection."""
import os
import psycopg2


def fetch_user(conn, username: str):
    with conn.cursor() as cur:
        cur.execute("SELECT id, email FROM users WHERE username = %s", (username,))
        return cur.fetchone()


def update_email(conn, user_id: int, new_email: str):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET email = %s WHERE id = %s",
            (new_email, user_id),
        )
    conn.commit()


if __name__ == "__main__":
    dsn = os.environ["DATABASE_URL"]  # config-controlled, not user-controlled
    with psycopg2.connect(dsn) as conn:
        row = fetch_user(conn, "alice")
        print(row)
