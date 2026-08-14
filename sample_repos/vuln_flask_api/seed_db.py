"""Sandbox-container fixture setup — NOT part of the vulnerable app itself.

Seeds orders.db with a couple of rows so /orders/search has real data to
differ against when P4's verify stage checks the SQL injection finding for
real (a normal request should return one customer's rows; the injected
payload should return all of them).
"""
import sqlite3

conn = sqlite3.connect("orders.db")
conn.execute(
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, item TEXT, total REAL, customer TEXT)"
)
conn.executemany(
    "INSERT INTO orders (item, total, customer) VALUES (?, ?, ?)",
    [
        ("Widget", 19.99, "alice"),
        ("Gadget", 49.50, "bob"),
        ("Gizmo", 9.99, "bob"),
    ],
)
conn.commit()
conn.close()
