import streamlit as st
import sqlite3
import hashlib
import os
import app  # Import the app module

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_user_directory(email):
    # Create a directory for the user to store files
    user_directory = f"./user_data/{email}"
    os.makedirs(user_directory, exist_ok=True)
    return user_directory

def create_user(first_name, last_name, phone_no, email, password):
    conn = sqlite3.connect('allusers.db')
    c = conn.cursor()
    # Check if the email already exists
    c.execute('SELECT * FROM users WHERE email = ?', (email,))
    if c.fetchone():
        st.error("Email already exists. Please use a different one.")
    else:
        directory = create_user_directory(email)  # Create and get the user directory
        c.execute('INSERT INTO users (first_name, last_name, phone_no, email, password, directory) VALUES (?, ?, ?, ?, ?, ?)', 
                  (first_name, last_name, phone_no, email, hash_password(password), directory))
        conn.commit()
        st.success("User registered successfully!")
    conn.close()

def check_login(email, password):
    conn = sqlite3.connect('allusers.db')
    c = conn.cursor()
    c.execute('SELECT password FROM users WHERE email = ?', (email,))
    stored_password = c.fetchone()
    conn.close()
    if stored_password and stored_password[0] == hash_password(password):
        return True
    return False

def get_user_info(email):
    conn = sqlite3.connect('allusers.db')
    c = conn.cursor()
    c.execute('SELECT id, first_name, last_name, directory FROM users WHERE email = ?', (email,))
    user_info = c.fetchone()
    conn.close()
    return user_info

def login():
    st.title("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if check_login(email, password):
            user_info = get_user_info(email)
            if user_info:
                st.session_state.logged_in = True
                st.session_state.user_id = user_info[0]
                st.session_state.full_name = f"{user_info[1]} {user_info[2]}"
                st.session_state.user_directory = user_info[3]
                st.experimental_rerun()  # This will reload the page
        else:
            st.error("Invalid email or password")

def register():
    st.title("Register")
    col1, col2 = st.columns(2)
    with col1:
        first_name = st.text_input("First Name")
    with col2:
        last_name = st.text_input("Last Name")
    phone_no = st.text_input("Phone Number")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    password_confirm = st.text_input("Confirm Password", type="password")
    if st.button("Register"):
        if password == password_confirm:
            if first_name and last_name and phone_no and email and password:
                create_user(first_name, last_name, phone_no, email, password)
            else:
                st.error("Please fill out all fields")
        else:
            st.error("Passwords do not match")

def main():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if st.session_state.logged_in:
        app.main()  # Call the main function from app.py
    else:
        menu = ["Login", "Register"]
        choice = st.sidebar.selectbox("Menu", menu)

        if choice == "Login":
            login()
        elif choice == "Register":
            register()

if __name__ == "__main__":
    main()
