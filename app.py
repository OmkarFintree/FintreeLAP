import streamlit as st
from streamlit_option_menu import option_menu
from pymongo import MongoClient
import hashlib
import pandas as pd
import base64
import io
from datetime import datetime

st.set_page_config(
    page_icon="🌳",
    page_title="Fintree Finance LAP"
)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["Fintree_Finance"]
users_collection = db["users"]
admins_collection = db["admins"]
customers_collection = db["customers"]
permissions_collection = db["permissions"]
update_logs_collection = db["update_logs"]
deleted_users_collection = db["deleted_users"]

# Helper function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Register a new user
def register_user(username, password, contact_number):
    if users_collection.find_one({"username": username}) or admins_collection.find_one({"username": username}):
        st.warning("Username already exists. Please choose a different username.")
    elif users_collection.find_one({"contact_number": contact_number}):
        st.warning("Contact number already exists. Please choose a different contact number.")
    else:
        hashed_password = hash_password(password)
        users_collection.insert_one({"username": username, "password": hashed_password, "contact_number": contact_number})
        
        # Check if the user was previously deleted
        if deleted_users_collection.find_one({"username": username, "contact_number": contact_number}):
            permissions_collection.insert_one({"username": username, "permissions": []})  # No default permissions
            st.warning("You need to request access to the tabs from the admin again.")
        else:
            permissions_collection.insert_one({"username": username, "permissions": []})  # No default permissions
        
        st.success("User registered successfully!")
        st.session_state.user_logged_in = True
        st.session_state.username = username
        st.experimental_rerun()

# Authenticate user
def authenticate_user(username, password):
    hashed_password = hash_password(password)
    user = users_collection.find_one({"username": username, "password": hashed_password})
    return user

# Authenticate admin
def authenticate_admin(username, password):
    hashed_password = hash_password(password)
    admin = admins_collection.find_one({"username": username, "password": hashed_password})
    return admin

# Verify username and contact number
def verify_user_contact(username, contact_number):
    user = users_collection.find_one({"username": username, "contact_number": contact_number})
    return user

# Reset password
def reset_password(username, new_password):
    hashed_password = hash_password(new_password)
    users_collection.update_one({"username": username}, {"$set": {"password": hashed_password}})
    st.success("You have successfully reset your password!")
    st.session_state.password_reset = True

# Admin access check
def admin_login(username, password):
    main_admin_login = (username == "omadmin" and password == "ompass")
    admin = admins_collection.find_one({"username": username, "password": hash_password(password)})
    return main_admin_login or admin

# Generate a unique customer ID
def generate_unique_id():
    latest_customer = customers_collection.find_one(sort=[("customer_id", -1)])
    if latest_customer:
        return latest_customer["customer_id"] + 1
    return 1

# Convert uploaded file to binary and create a hash
def file_to_binary(uploaded_file):
    if uploaded_file is not None:
        file_data = uploaded_file.read()
        file_hash = hashlib.sha256(file_data).hexdigest()[:10]  # Short hash for display
        return file_data, file_hash
    return None, None

# Display PDF using base64 encoding
def display_pdf(pdf_data):
    if pdf_data:
        base64_pdf = base64.b64encode(pdf_data).decode('utf-8')
        pdf_display = F'<iframe src="data:application/pdf;base64,{base64_pdf}" width="100%" height="500px" type="application/pdf"></iframe>'
        st.markdown(pdf_display, unsafe_allow_html=True)

# Log updates
def log_update(username, update_details, original_data):
    changes = []
    for key, new_value in update_details.items():
        old_value = original_data.get(key, 'N/A')
        if isinstance(old_value, bytes):
            old_value = hashlib.sha256(old_value).hexdigest()[:10]  # Short hash for binary data
        if isinstance(new_value, bytes):
            new_value = hashlib.sha256(new_value).hexdigest()[:10]  # Short hash for binary data
        changes.append({
            "field": key,
            "old_value": old_value,
            "new_value": new_value
        })
    update_logs_collection.insert_one({"username": username, "changes": changes, "timestamp": pd.Timestamp.now()})

# Helper function to convert date to string
def date_to_str(date):
    return date.strftime('%Y-%m-%d')

# Initialize session state for admin and user panels
if 'admin_logged_in' not in st.session_state:
    st.session_state.admin_logged_in = False
if 'user_logged_in' not in st.session_state:
    st.session_state.user_logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ''
if 'update_customer_id' not in st.session_state:
    st.session_state.update_customer_id = None
if 'password_reset' not in st.session_state:
    st.session_state.password_reset = False
if 'admin_previous_tab' not in st.session_state:
    st.session_state.admin_previous_tab = None
if 'user_previous_tab' not in st.session_state:
    st.session_state.user_previous_tab = None

# Function to clear tab-specific session state
def clear_tab_session():
    st.session_state.rm_customer = None
    st.session_state.customer_details = None
    st.session_state.status_customer = None
    st.session_state.update_customer_id = None

# Streamlit app
st.title("Fintree Finance LAP")

if not st.session_state.admin_logged_in and not st.session_state.user_logged_in:
    # Tabs
    tabs = ["Login", "Register", "Forgot Password", "Admin"]
    tab = st.tabs(tabs)

    with tab[0]:
        st.header("Login")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            if username and password:
                user = authenticate_user(username, password)
                if user:
                    st.success("Logged in successfully!")
                    st.session_state.user_logged_in = True
                    st.session_state.username = username
                    st.experimental_rerun()
                else:
                    st.error("Invalid username or password")
            else:
                st.warning("Please fill in all fields.")

    with tab[1]:
        st.header("Register")
        username = st.text_input("New Username", key="register_username")
        password = st.text_input("New Password", type="password", key="register_password")
        contact_number = st.text_input("Contact Number (10 digits)", max_chars=10, key="register_contact_number")
        if st.button("Register"):
            if username and password and contact_number:
                if len(contact_number) != 10 or not contact_number.isdigit():
                    st.warning("Please enter a valid 10-digit contact number.")
                else:
                    register_user(username, password, contact_number)
            else:
                st.warning("Please fill in all fields.")

    with tab[2]:
        st.header("Forgot Password")
        username = st.text_input("Username", key="forgot_username")
        contact_number = st.text_input("Contact Number", max_chars=10, key="forgot_contact_number")

        if st.button("Verify"):
            if username and contact_number:
                user = verify_user_contact(username, contact_number)
                if user:
                    st.session_state.user_verified = True
                    st.session_state.username_to_reset = username
                    st.experimental_rerun()
                else:
                    st.warning("Invalid username or contact number.")
            else:
                st.warning("Please fill in all fields.")

        if 'user_verified' in st.session_state and st.session_state.user_verified:
            new_password = st.text_input("New Password", type="password", key="forgot_new_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="forgot_confirm_password")
            if st.button("Reset Password"):
                if new_password and confirm_password:
                    if new_password == confirm_password:
                        reset_password(st.session_state.username_to_reset, new_password)
                        st.success("You have successfully reset your password!")
                        st.experimental_set_query_params(tab="Login")
                        st.session_state.user_verified = False  # Reset user_verified after password reset
                        st.experimental_rerun()
                    else:
                        st.warning("Passwords do not match. Please try again.")
                else:
                    st.warning("Please fill in all fields.")

    if st.session_state.password_reset:
        st.experimental_set_query_params(tab="Login")
        st.session_state.password_reset = False
        st.experimental_rerun()

    with tab[3]:
        st.header("Admin Login")
        admin_username = st.text_input("Admin Username", key="admin_username")
        admin_password = st.text_input("Admin Password", type="password", key="admin_password")
        if st.button("Admin Login"):
            if admin_username and admin_password:
                if admin_login(admin_username, admin_password):
                    st.success("Admin logged in successfully!")
                    st.session_state.admin_logged_in = True
                    st.session_state.username = admin_username
                    st.experimental_rerun()
                else:
                    st.error("Invalid admin username or password")
            else:
                st.warning("Please fill in all fields.")

elif st.session_state.admin_logged_in:
    with st.sidebar:
        st.sidebar.title(f"Welcome, {st.session_state.username}!")
        selected = option_menu(
            menu_title="Admin Panel",
            options=["Channel", "Customer", "Login", "Sanction/Reject", "Disbursement 1/2", "STATUS", "UPDATE", "DOWNLOAD", "Admin Control", "User Control", "TRACE USER"],
            icons=["person-plus", "people", "eye", "pencil", "download", "gear", "people", "search"],
            menu_icon="cast",
            default_index=0,
            orientation="vertical",
        )

    # Clear session state when switching tabs
    if st.session_state.admin_previous_tab != selected:
        clear_tab_session()
        st.session_state.admin_previous_tab = selected

    st.sidebar.button("Logout", on_click=lambda: st.session_state.update({"admin_logged_in": False, "username": ''}))

    if selected == "Channel":
        st.subheader("Channel Tab")
        unique_id = generate_unique_id()
        st.write(f"Unique Customer ID: {unique_id}")
        with st.form("add_customer_form"):
            product = st.selectbox("Product", ["Secured", "Unsecured"], key="admin_product")
            customer_type = st.selectbox("Type", ["Direct", "Referral", "Connector"], key="admin_customer_type")
            location = st.selectbox("Location", ["Mumbai", "Kalyan", "Panvel", "Kolhapur"], key="admin_location")
            name = st.text_input("Name", key="admin_name")
            entity_type = st.selectbox("Type of Entity", ["Individual", "Proprietor", "Partnership", "LLP", "Pvt Ltd"], key="admin_entity_type")
            contact_person = st.text_input("Contact Person", key="admin_contact_person")
            mobile_1 = st.text_input("Mobile 1", max_chars=10, key="admin_mobile_1")
            mobile_2 = st.text_input("Mobile 2", max_chars=10, key="admin_mobile_2")

            signed_agreement = st.file_uploader("Upload Signed Agreement", type=["pdf"], key="admin_signed_agreement")

            pan = st.file_uploader("Upload PAN", type=["pdf"], key="admin_pan")

            cancelled_cheque = st.file_uploader("Upload Cancelled Cheque", type=["pdf"], key="admin_cancelled_cheque")

            gst = st.file_uploader("Upload GST", type=["pdf"], key="admin_gst")

            shop_certificate = st.file_uploader("Upload Shop Establishment Certificate", type=["pdf"], key="admin_shop_certificate")

            partnership_deed = st.file_uploader("Upload Partnership Deed", type=["pdf"], key="admin_partnership_deed")

            incorporation_certificate = st.file_uploader("Upload Certificate of Incorporation", type=["pdf"], key="admin_incorporation_certificate")

            other_queries = st.text_area("Other Queries", key="admin_other_queries")

            submitted = st.form_submit_button("Submit")
            if submitted:
                if not name or not contact_person or not mobile_1 or not mobile_2:
                    st.warning("Please fill in all required fields.")
                else:
                    customer_data = {
                        "customer_id": unique_id,
                        "product": product,
                        "customer_type": customer_type,
                        "location": location,
                        "name": name,
                        "entity_type": entity_type,
                        "contact_person": contact_person,
                        "mobile_1": mobile_1,
                        "mobile_2": mobile_2,
                        "signed_agreement": file_to_binary(signed_agreement)[0] if signed_agreement else None,
                        "pan": file_to_binary(pan)[0] if pan else None,
                        "cancelled_cheque": file_to_binary(cancelled_cheque)[0] if cancelled_cheque else None,
                        "gst": file_to_binary(gst)[0] if gst else None,
                        "shop_certificate": file_to_binary(shop_certificate)[0] if shop_certificate else None,
                        "partnership_deed": file_to_binary(partnership_deed)[0] if partnership_deed else None,
                        "incorporation_certificate": file_to_binary(incorporation_certificate)[0] if incorporation_certificate else None,
                        "other_queries": other_queries
                    }
                    customers_collection.insert_one(customer_data)
                    st.success(f"Customer details added successfully! Customer ID: {unique_id}")

    elif selected == "Customer":
        st.subheader("Customer")
        if 'rm_customer' not in st.session_state:
            st.session_state.rm_customer = None

        with st.form("rm_form_admin"):
            unique_id = st.selectbox("Select Customer ID", options=[c['customer_id'] for c in customers_collection.find()], key="admin_rm_customer_id")
            fetch_submitted = st.form_submit_button("Fetch Details")

        if fetch_submitted or st.session_state.rm_customer:
            if fetch_submitted:
                st.session_state.rm_customer = customers_collection.find_one({"customer_id": int(unique_id)})
            customer = st.session_state.rm_customer
            if customer:
                st.write("Customer Details:")
                st.write(f"Name: {customer['name']}")
                st.write(f"Location: {customer['location']}")
                st.write(f"Contact Person: {customer['contact_person']}")
                st.write(f"Mobile 1: {customer['mobile_1']}")
                st.write(f"Mobile 2: {customer['mobile_2']}")
                with st.form("rm_details_form_admin"):
                    rm_name = st.selectbox("RM Name", ["Omkar", "Dhananjay", "Nagesh", "Prafull", "Sachin", "Forid", "Yuvraj"], index=0, key="admin_rm_name")
                    location = st.selectbox("Location", ["Mumbai", "Kalyan", "Panvel", "Kolhapur"], index=0, key="admin_rm_location")
                    financier = st.selectbox("Financier", ["Chola Micro", "Chola Prime"], index=0, key="admin_rm_financier")
                    loan_type = st.selectbox("Loan Type", ["LAP", "Commercial Purchase", "Balance Transfer"], index=0, key="admin_rm_loan_type")
                    application = st.selectbox("Application", ["Company", "Individual"], index=0, key="admin_rm_application")
                    name = st.text_input("Name", value=customer["name"], key="admin_rm_name_input")
                    mobile_number = st.text_input("Mobile Number", value=customer["mobile_1"], key="admin_rm_mobile_number")
                    loan_amount = st.number_input("Loan Amount", min_value=0, value=customer.get("loan_amount", 0), key="admin_rm_loan_amount")
                    if st.form_submit_button("Submit RM Details"):
                        customers_collection.update_one(
                            {"customer_id": int(unique_id)},
                            {"$set": {
                                "rm_name": rm_name,
                                "location_rm": location,
                                "financier": financier,
                                "loan_type": loan_type,
                                "application": application,
                                "loan_amount": loan_amount
                            }}
                        )
                        st.success("RM details submitted successfully.")
                        log_update(st.session_state.username, {
                            "customer_id": int(unique_id),
                            "rm_name": rm_name,
                            "location_rm": location,
                            "financier": financier,
                            "loan_type": loan_type,
                            "application": application,
                            "loan_amount": loan_amount
                        }, customer)
                        st.session_state.rm_customer = None

    elif selected == "Login":
        st.subheader("Login Tab")
        if 'customer_details' not in st.session_state:
            st.session_state.customer_details = None

        with st.form("login_form_admin"):
            unique_id = st.selectbox("Select Customer ID", options=[c['customer_id'] for c in customers_collection.find()], key="admin_login_customer_id")
            fetch_submitted = st.form_submit_button("Fetch Details")

        if fetch_submitted or st.session_state.customer_details:
            if fetch_submitted:
                st.session_state.customer_details = customers_collection.find_one({"customer_id": int(unique_id)})
            customer = st.session_state.customer_details
            if customer:
                st.write("Customer Details:")
                st.write(f"Name: {customer['name']}")
                st.write(f"Location: {customer['location']}")
                st.write(f"Contact Person: {customer['contact_person']}")
                st.write(f"Mobile 1: {customer['mobile_1']}")
                st.write(f"Mobile 2: {customer['mobile_2']}")

                with st.form("login_form"):
                    date = st.date_input("Date", key="login_date")
                    amount = st.number_input("Amount", min_value=0.0, format="%.2f", key="login_amount")
                    if st.form_submit_button("Submit"):
                        login_data = {
                            "login_date": date_to_str(date),
                            "login_amount": amount
                        }
                        customers_collection.update_one(
                            {"customer_id": int(unique_id)},
                            {"$set": login_data}
                        )
                        st.success("Login data submitted successfully.")

    elif selected == "Sanction/Reject":
        st.subheader("Sanction/Reject Tab")
        if 'customer_details' not in st.session_state:
            st.session_state.customer_details = None

        with st.form("sanction_reject_form_admin"):
            unique_id = st.selectbox("Select Customer ID", options=[c['customer_id'] for c in customers_collection.find()], key="admin_sanction_reject_customer_id")
            fetch_submitted = st.form_submit_button("Fetch Details")

        if fetch_submitted or st.session_state.customer_details:
            if fetch_submitted:
                st.session_state.customer_details = customers_collection.find_one({"customer_id": int(unique_id)})
            customer = st.session_state.customer_details
            if customer:
                st.write("Customer Details:")
                st.write(f"Name: {customer['name']}")
                st.write(f"Location: {customer['location']}")
                st.write(f"Contact Person: {customer['contact_person']}")
                st.write(f"Mobile 1: {customer['mobile_1']}")
                st.write(f"Mobile 2: {customer['mobile_2']}")

                with st.form("sanction_reject_form"):
                    date = st.date_input("Date", key="sanction_reject_date")
                    amount = st.number_input("Amount", min_value=0.0, format="%.2f", key="sanction_reject_amount")
                    status = st.selectbox("Customer Case Status", ["Rejected", "Sanctioned"], key="sanction_reject_status")
                    if st.form_submit_button("Submit"):
                        sanction_reject_data = {
                            "sanction_date": date_to_str(date),
                            "sanction_amount": amount,
                            "sanction_status": status
                        }
                        customers_collection.update_one(
                            {"customer_id": int(unique_id)},
                            {"$set": sanction_reject_data}
                        )
                        st.success("Sanction/Reject data submitted successfully.")

    elif selected == "Disbursement 1/2":
        st.subheader("Disbursement 1/2 Tab")
        if 'customer_details' not in st.session_state:
            st.session_state.customer_details = None

        with st.form("disbursement_form_admin"):
            unique_id = st.selectbox("Select Customer ID", options=[c['customer_id'] for c in customers_collection.find()], key="admin_disbursement_customer_id")
            fetch_submitted = st.form_submit_button("Fetch Details")

        if fetch_submitted or st.session_state.customer_details:
            if fetch_submitted:
                st.session_state.customer_details = customers_collection.find_one({"customer_id": int(unique_id)})
            customer = st.session_state.customer_details
            if customer:
                st.write("Customer Details:")
                st.write(f"Name: {customer['name']}")
                st.write(f"Location: {customer['location']}")
                st.write(f"Contact Person: {customer['contact_person']}")
                st.write(f"Mobile 1: {customer['mobile_1']}")
                st.write(f"Mobile 2: {customer['mobile_2']}")

                with st.form("disbursement_form"):
                    date = st.date_input("Date", key="disbursement_date")
                    amount = st.number_input("Amount", min_value=0.0, format="%.2f", key="disbursement_amount")
                    offered_roi = st.number_input("Offered ROI (%)", min_value=0.0, format="%.2f", key="disbursement_offered_roi")
                    processing_fees = st.number_input("Processing Fees", min_value=0.0, format="%.2f", key="disbursement_processing_fees")
                    insurance_amount = st.number_input("Insurance Amount", min_value=0.0, format="%.2f", key="disbursement_insurance_amount")
                    if st.form_submit_button("Submit"):
                        disbursement_data = {
                            "disbursement_date": date_to_str(date),
                            "disbursement_amount": amount,
                            "offered_roi": offered_roi,
                            "processing_fees": processing_fees,
                            "insurance_amount": insurance_amount
                        }
                        customers_collection.update_one(
                            {"customer_id": int(unique_id)},
                            {"$set": disbursement_data}
                        )
                        st.success("Disbursement data submitted successfully.")

    elif selected == "STATUS":
        st.subheader("STATUS")
        if 'status_customer' not in st.session_state:
            st.session_state.status_customer = None

        with st.form("status_form_admin"):
            unique_id = st.selectbox("Select Customer ID", options=[c['customer_id'] for c in customers_collection.find()], key="admin_status_customer_id")
            if st.form_submit_button("Fetch Details"):
                if unique_id:
                    customer = customers_collection.find_one({"customer_id": int(unique_id)})
                    st.session_state.status_customer = customer

        if st.session_state.status_customer:
            customer = st.session_state.status_customer
            st.write("Customer Details:")
            st.write(f"Product: {customer['product']}")
            st.write(f"Type: {customer['customer_type']}")
            st.write(f"Location: {customer['location']}")
            st.write(f"Name: {customer['name']}")
            st.write(f"Type of Entity: {customer['entity_type']}")
            st.write(f"Contact Person: {customer['contact_person']}")
            st.write(f"Mobile 1: {customer['mobile_1']}")
            st.write(f"Mobile 2: {customer['mobile_2']}")
            st.write(f"RM Name: {customer.get('rm_name', 'Not Assigned')}")
            st.write(f"RM Location: {customer.get('location_rm', 'Not Assigned')}")
            st.write(f"Financier: {customer.get('financier', 'Not Assigned')}")
            st.write(f"Loan Type: {customer.get('loan_type', 'Not Assigned')}")
            st.write(f"Application: {customer.get('application', 'Not Assigned')}")
            st.write(f"Loan Amount: {customer.get('loan_amount', 'Not Assigned')}")
            st.write(f"Login Date: {customer.get('login_date', 'Not Assigned')}")
            st.write(f"Login Amount: {customer.get('login_amount', 'Not Assigned')}")
            st.write(f"Sanction Date: {customer.get('sanction_date', 'Not Assigned')}")
            st.write(f"Sanction Amount: {customer.get('sanction_amount', 'Not Assigned')}")
            st.write(f"Sanction Status: {customer.get('sanction_status', 'Not Assigned')}")
            st.write(f"Disbursement Date: {customer.get('disbursement_date', 'Not Assigned')}")
            st.write(f"Disbursement Amount: {customer.get('disbursement_amount', 'Not Assigned')}")
            st.write(f"Offered ROI: {customer.get('offered_roi', 'Not Assigned')}")
            st.write(f"Processing Fees: {customer.get('processing_fees', 'Not Assigned')}")
            st.write(f"Insurance Amount: {customer.get('insurance_amount', 'Not Assigned')}")
            st.write(f"Other Queries: {customer.get('other_queries', 'Not Provided')}")

            # Display PDFs and download links outside the form
            for doc in ["signed_agreement", "pan", "cancelled_cheque", "gst", "shop_certificate", "partnership_deed", "incorporation_certificate"]:
                if customer.get(doc):
                    st.write(f"{doc.replace('_', ' ').title()}:")
                    display_pdf(customer[doc])
                    st.download_button(
                        label=f"Download {doc.replace('_', ' ').title()}",
                        data=customer[doc],
                        file_name=f"{customer['name']}_{doc}.pdf",
                        mime="application/pdf"
                    )

        if st.button("Show All Data"):
            df = pd.DataFrame(list(customers_collection.find()))
            st.dataframe(df)

    elif selected == "UPDATE":
        st.subheader("Update Tab")

        # Always show the search box with the dropdown
        unique_ids = [c['customer_id'] for c in customers_collection.find()]
        with st.form("fetch_update_form_admin"):
            unique_id = st.selectbox("Select Customer ID to Update", options=unique_ids, key="fetch_update_customer_id_admin")
            fetch_submitted = st.form_submit_button("Fetch Details")

        if fetch_submitted:
            st.session_state.update_customer_id = unique_id

        if st.session_state.update_customer_id is not None:
            customer = customers_collection.find_one({"customer_id": int(st.session_state.update_customer_id)})
            if customer:
                with st.form("update_customer_form_admin"):
                    st.write("Channel Information")
                    product = st.selectbox("Product", ["Secured", "Unsecured"], index=["Secured", "Unsecured"].index(customer["product"]), key="admin_update_product")
                    customer_type = st.selectbox("Type", ["Direct", "Referral", "Connector"], index=["Direct", "Referral", "Connector"].index(customer["customer_type"]), key="admin_update_customer_type")
                    location = st.selectbox("Location", ["Mumbai", "Kalyan", "Panvel", "Kolhapur"], index=["Mumbai", "Kalyan", "Panvel", "Kolhapur"].index(customer["location"]), key="admin_update_location")
                    name = st.text_input("Name", value=customer["name"], key="admin_update_name")
                    entity_type = st.selectbox("Type of Entity", ["Individual", "Proprietor", "Partnership", "LLP", "Pvt Ltd"], index=["Individual", "Proprietor", "Partnership", "LLP", "Pvt Ltd"].index(customer["entity_type"]), key="admin_update_entity_type")
                    contact_person = st.text_input("Contact Person", value=customer["contact_person"], key="admin_update_contact_person")
                    mobile_1 = st.text_input("Mobile 1", value=customer["mobile_1"], max_chars=10, key="admin_update_mobile_1")
                    mobile_2 = st.text_input("Mobile 2", value=customer["mobile_2"], max_chars=10, key="admin_update_mobile_2")

                    signed_agreement = st.file_uploader("Upload Signed Agreement", type=["pdf"], key="admin_update_signed_agreement")

                    pan = st.file_uploader("Upload PAN", type=["pdf"], key="admin_update_pan")

                    cancelled_cheque = st.file_uploader("Upload Cancelled Cheque", type=["pdf"], key="admin_update_cancelled_cheque")

                    gst = st.file_uploader("Upload GST", type=["pdf"], key="admin_update_gst")

                    shop_certificate = st.file_uploader("Upload Shop Establishment Certificate", type=["pdf"], key="admin_update_shop_certificate")

                    partnership_deed = st.file_uploader("Upload Partnership Deed", type=["pdf"], key="admin_update_partnership_deed")

                    incorporation_certificate = st.file_uploader("Upload Certificate of Incorporation", type=["pdf"], key="admin_update_incorporation_certificate")

                    other_queries = st.text_area("Other Queries", value=customer.get("other_queries", ''), key="admin_update_other_queries")

                    st.write("Customer Information")
                    rm_name = st.selectbox("RM Name", ["Omkar", "Dhananjay", "Nagesh", "Prafull", "Sachin", "Forid", "Yuvraj"], index=0, key="admin_update_rm_name")
                    location_rm = st.selectbox("Location", ["Mumbai", "Kalyan", "Panvel", "Kolhapur"], index=0, key="admin_update_location_rm")
                    financier = st.selectbox("Financier", ["Chola Micro", "Chola Prime"], index=0, key="admin_update_financier")
                    loan_type = st.selectbox("Loan Type", ["LAP", "Commercial Purchase", "Balance Transfer"], index=0, key="admin_update_loan_type")
                    application = st.selectbox("Application", ["Company", "Individual"], index=0, key="admin_update_application")
                    loan_amount = st.number_input("Loan Amount", min_value=0, value=customer.get("loan_amount", 0), key="admin_update_loan_amount")

                    st.write("Login Information")
                    login_date = st.date_input("Login Date", key="admin_update_login_date", value=datetime.strptime(customer.get("login_date", datetime.now().date().strftime('%Y-%m-%d')), '%Y-%m-%d').date())
                    login_amount = st.number_input("Login Amount", min_value=0.0, format="%.2f", key="admin_update_login_amount", value=customer.get("login_amount", 0.0))

                    st.write("Sanction/Reject Information")
                    sanction_date = st.date_input("Sanction Date", key="admin_update_sanction_date", value=datetime.strptime(customer.get("sanction_date", datetime.now().date().strftime('%Y-%m-%d')), '%Y-%m-%d').date())
                    sanction_amount = st.number_input("Sanction Amount", min_value=0.0, format="%.2f", key="admin_update_sanction_amount", value=customer.get("sanction_amount", 0.0))
                    sanction_status = st.selectbox("Sanction Status", ["Rejected", "Sanctioned"], key="admin_update_sanction_status", index=["Rejected", "Sanctioned"].index(customer.get("sanction_status", "Rejected")))

                    st.write("Disbursement Information")
                    disbursement_date = st.date_input("Disbursement Date", key="admin_update_disbursement_date", value=datetime.strptime(customer.get("disbursement_date", datetime.now().date().strftime('%Y-%m-%d')), '%Y-%m-%d').date())
                    disbursement_amount = st.number_input("Disbursement Amount", min_value=0.0, format="%.2f", key="admin_update_disbursement_amount", value=customer.get("disbursement_amount", 0.0))
                    offered_roi = st.number_input("Offered ROI (%)", min_value=0.0, format="%.2f", key="admin_update_offered_roi", value=customer.get("offered_roi", 0.0))
                    processing_fees = st.number_input("Processing Fees", min_value=0.0, format="%.2f", key="admin_update_processing_fees", value=customer.get("processing_fees", 0.0))
                    insurance_amount = st.number_input("Insurance Amount", min_value=0.0, format="%.2f", key="admin_update_insurance_amount", value=customer.get("insurance_amount", 0.0))

                    update_submitted = st.form_submit_button("Update")
                    if update_submitted:
                        updated_customer_data = {
                            "product": product,
                            "customer_type": customer_type,
                            "location": location,
                            "name": name,
                            "entity_type": entity_type,
                            "contact_person": contact_person,
                            "mobile_1": mobile_1,
                            "mobile_2": mobile_2,
                            "signed_agreement": file_to_binary(signed_agreement)[0] if signed_agreement else customer["signed_agreement"],
                            "pan": file_to_binary(pan)[0] if pan else customer["pan"],
                            "cancelled_cheque": file_to_binary(cancelled_cheque)[0] if cancelled_cheque else customer["cancelled_cheque"],
                            "gst": file_to_binary(gst)[0] if gst else customer["gst"],
                            "shop_certificate": file_to_binary(shop_certificate)[0] if shop_certificate else customer["shop_certificate"],
                            "partnership_deed": file_to_binary(partnership_deed)[0] if partnership_deed else customer["partnership_deed"],
                            "incorporation_certificate": file_to_binary(incorporation_certificate)[0] if incorporation_certificate else customer["incorporation_certificate"],
                            "other_queries": other_queries,
                            "rm_name": rm_name,
                            "location_rm": location_rm,
                            "financier": financier,
                            "loan_type": loan_type,
                            "application": application,
                            "loan_amount": loan_amount,
                            "login_date": date_to_str(login_date),
                            "login_amount": login_amount,
                            "sanction_date": date_to_str(sanction_date),
                            "sanction_amount": sanction_amount,
                            "sanction_status": sanction_status,
                            "disbursement_date": date_to_str(disbursement_date),
                            "disbursement_amount": disbursement_amount,
                            "offered_roi": offered_roi,
                            "processing_fees": processing_fees,
                            "insurance_amount": insurance_amount
                        }
                        customers_collection.update_one({"customer_id": int(st.session_state.update_customer_id)}, {"$set": updated_customer_data})
                        st.success(f"You have successfully updated the customer data for Customer ID: {st.session_state.update_customer_id}")
                        log_update(st.session_state.username, updated_customer_data, customer)
                        st.session_state.update_customer_id = None  # Reset the session state after update

    elif selected == "DOWNLOAD":
        st.subheader("Download Tab")
        df = pd.DataFrame(list(users_collection.find()))
        towrite = io.BytesIO()
        df.to_excel(towrite, index=False, engine='xlsxwriter')
        towrite.seek(0)
        st.download_button(
            label="Download user data",
            data=towrite,
            file_name="user_data.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

    elif selected == "Admin Control":
        st.subheader("Admin Control Tab")
        admin_control_tabs = st.tabs(["New Admin", "Delete Admin"])

        with admin_control_tabs[0]:
            st.subheader("Create New Admin")
            with st.form("create_admin_form"):
                new_admin_username = st.text_input("New Admin Username")
                new_admin_password = st.text_input("New Admin Password", type="password")
                if st.form_submit_button("Create Admin"):
                    if new_admin_username and new_admin_password:
                        if admins_collection.find_one({"username": new_admin_username}) or users_collection.find_one({"username": new_admin_username}):
                            st.warning("Admin username already exists. Please choose a different username.")
                        else:
                            hashed_password = hash_password(new_admin_password)
                            admins_collection.insert_one({"username": new_admin_username, "password": hashed_password})
                            st.success(f"New admin {new_admin_username} created successfully!")
                    else:
                        st.warning("Please fill in all fields.")

        with admin_control_tabs[1]:
            st.subheader("Delete Admin")
            admin_list = list(admins_collection.find())
            for admin in admin_list:
                if admin["username"] != "omadmin":  # Prevent deletion of main admin
                    st.write(f"{admin['username']}")
                    if st.button(f"Delete {admin['username']}", key=f"delete_{admin['_id']}"):
                        admins_collection.delete_one({"_id": admin["_id"]})
                        st.success(f"Admin {admin['username']} deleted successfully!")
                        st.experimental_rerun()  # Refresh the page to reflect changes

    elif selected == "User Control":
        st.subheader("User Control Tab")
        user_control_tabs = st.tabs(["User Permissions", "Total Users"])

        with user_control_tabs[0]:
            st.subheader("User Permissions")
            users = list(users_collection.find())
            usernames = [user['username'] for user in users]
            selected_user = st.selectbox("Select User", usernames)
            user_permissions = permissions_collection.find_one({"username": selected_user})
            permissions = user_permissions["permissions"] if user_permissions else []
            with st.form(f"user_permissions_form_{selected_user}"):
                st.write(f"Permissions for {selected_user}:")
                channel = st.checkbox("Channel", value="Channel" in permissions)
                customer = st.checkbox("Customer", value="Customer" in permissions)
                login = st.checkbox("Login", value="Login" in permissions)
                sanction_reject = st.checkbox("Sanction/Reject", value="Sanction/Reject" in permissions)
                disbursement = st.checkbox("Disbursement 1/2", value="Disbursement 1/2" in permissions)
                status = st.checkbox("STATUS", value="STATUS" in permissions)
                update = st.checkbox("UPDATE", value="UPDATE" in permissions)
                download = st.checkbox("DOWNLOAD", value="DOWNLOAD" in permissions)
                submitted = st.form_submit_button("Update Permissions")
                if submitted:
                    new_permissions = []
                    if channel:
                        new_permissions.append("Channel")
                    if customer:
                        new_permissions.append("Customer")
                    if login:
                        new_permissions.append("Login")
                    if sanction_reject:
                        new_permissions.append("Sanction/Reject")
                    if disbursement:
                        new_permissions.append("Disbursement 1/2")
                    if status:
                        new_permissions.append("STATUS")
                    if update:
                        new_permissions.append("UPDATE")
                    if download:
                        new_permissions.append("DOWNLOAD")
                    permissions_collection.update_one({"username": selected_user}, {"$set": {"permissions": new_permissions}}, upsert=True)
                    st.success(f"Permissions updated for {selected_user}")

        with user_control_tabs[1]:
            st.subheader("Total Users")
            users = list(users_collection.find())
            for user in users:
                st.write(f"{user['username']}")
                if st.button(f"Delete {user['username']}", key=f"delete_user_{user['_id']}"):
                    users_collection.delete_one({"_id": user["_id"]})
                    permissions_collection.delete_one({"username": user["username"]})
                    # Log deleted user for re-registration checks
                    deleted_users_collection.insert_one({"username": user["username"], "contact_number": user["contact_number"]})
                    st.success(f"User {user['username']} deleted successfully!")
                    st.experimental_rerun()  # Refresh the page to reflect changes

    elif selected == "TRACE USER":
        st.subheader("TRACE USER")
        logs = list(update_logs_collection.find())
        if logs:
            log_data = []
            for log in logs:
                if 'changes' in log:
                    for change in log['changes']:
                        log_data.append({
                            "Timestamp": log['timestamp'],
                            "Username": log['username'],
                            "Field": change['field'],
                            "Old Value": change['old_value'],
                            "New Value": change['new_value']
                        })
            df = pd.DataFrame(log_data)

            st.table(df)

            # Create a download button for the log data
            towrite = io.BytesIO()
            df.to_excel(towrite, index=False, engine='xlsxwriter')
            towrite.seek(0)
            st.download_button(
                label="Download Logs",
                data=towrite,
                file_name="update_logs.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

            if st.button("Delete All Logs"):
                update_logs_collection.delete_many({})
                st.success("All logs have been deleted.")
                st.experimental_rerun()
        else:
            st.warning("No updates found.")

elif st.session_state.user_logged_in:
    user_permissions_doc = permissions_collection.find_one({"username": st.session_state.username})
    user_permissions = user_permissions_doc["permissions"] if user_permissions_doc else []
    
    st.title(f"Welcome, {st.session_state.username}!")
    
    if not user_permissions:
        st.write("The admin has not granted access to any tabs yet.")
    else:
        tab_titles = [title for title in user_permissions]
        user_tabs = st.tabs(tab_titles)

        tab_map = {title: i for i, title in enumerate(tab_titles)}

        if "Channel" in tab_map:
            with user_tabs[tab_map["Channel"]]:
                st.subheader("Channel")
                unique_id = generate_unique_id()
                st.write(f"Unique Customer ID: {unique_id}")
                with st.form("add_customer_form_user"):
                    product = st.selectbox("Product", ["Secured", "Unsecured"], key="user_product")
                    customer_type = st.selectbox("Type", ["Direct", "Referral", "Connector"], key="user_customer_type")
                    location = st.selectbox("Location", ["Mumbai", "Kalyan", "Panvel", "Kolhapur"], key="user_location")
                    name = st.text_input("Name", key="user_name")
                    entity_type = st.selectbox("Type of Entity", ["Individual", "Proprietor", "Partnership", "LLP", "Pvt Ltd"], key="user_entity_type")
                    contact_person = st.text_input("Contact Person", key="user_contact_person")
                    mobile_1 = st.text_input("Mobile 1", max_chars=10, key="user_mobile_1")
                    mobile_2 = st.text_input("Mobile 2", max_chars=10, key="user_mobile_2")

                    signed_agreement = st.file_uploader("Upload Signed Agreement", type=["pdf"], key="user_signed_agreement")

                    pan = st.file_uploader("Upload PAN", type=["pdf"], key="user_pan")

                    cancelled_cheque = st.file_uploader("Upload Cancelled Cheque", type=["pdf"], key="user_cancelled_cheque")

                    gst = st.file_uploader("Upload GST", type=["pdf"], key="user_gst")

                    shop_certificate = st.file_uploader("Upload Shop Establishment Certificate", type=["pdf"], key="user_shop_certificate")

                    partnership_deed = st.file_uploader("Upload Partnership Deed", type=["pdf"], key="user_partnership_deed")

                    incorporation_certificate = st.file_uploader("Upload Certificate of Incorporation", type=["pdf"], key="user_incorporation_certificate")

                    other_queries = st.text_area("Other Queries", key="user_other_queries")

                    submitted = st.form_submit_button("Submit")
                    if submitted:
                        if not name or not contact_person or not mobile_1 or not mobile_2:
                            st.warning("Please fill in all required fields.")
                        else:
                            customer_data = {
                                "customer_id": unique_id,
                                "username": st.session_state.username,
                                "product": product,
                                "customer_type": customer_type,
                                "location": location,
                                "name": name,
                                "entity_type": entity_type,
                                "contact_person": contact_person,
                                "mobile_1": mobile_1,
                                "mobile_2": mobile_2,
                                "signed_agreement": file_to_binary(signed_agreement)[0] if signed_agreement else None,
                                "pan": file_to_binary(pan)[0] if pan else None,
                                "cancelled_cheque": file_to_binary(cancelled_cheque)[0] if cancelled_cheque else None,
                                "gst": file_to_binary(gst)[0] if gst else None,
                                "shop_certificate": file_to_binary(shop_certificate)[0] if shop_certificate else None,
                                "partnership_deed": file_to_binary(partnership_deed)[0] if partnership_deed else None,
                                "incorporation_certificate": file_to_binary(incorporation_certificate)[0] if incorporation_certificate else None,
                                "other_queries": other_queries
                            }
                            customers_collection.insert_one(customer_data)
                            st.success(f"Customer details added successfully! Customer ID: {unique_id}")

        if "Customer" in tab_map:
            with user_tabs[tab_map["Customer"]]:
                st.subheader("Customer")
                if 'rm_customer' not in st.session_state:
                    st.session_state.rm_customer = None

                with st.form("rm_form_user"):
                    unique_id = st.selectbox("Select Customer ID", options=[c['customer_id'] for c in customers_collection.find({"username": st.session_state.username})], key="user_rm_customer_id")
                    fetch_submitted = st.form_submit_button("Fetch Details")

                if fetch_submitted or st.session_state.rm_customer:
                    if fetch_submitted:
                        st.session_state.rm_customer = customers_collection.find_one({"customer_id": int(unique_id), "username": st.session_state.username})
                    customer = st.session_state.rm_customer
                    if customer:
                        st.write("Customer Details:")
                        st.write(f"Name: {customer['name']}")
                        st.write(f"Location: {customer['location']}")
                        st.write(f"Contact Person: {customer['contact_person']}")
                        st.write(f"Mobile 1: {customer['mobile_1']}")
                        st.write(f"Mobile 2: {customer['mobile_2']}")
                        with st.form("rm_details_form_user"):
                            rm_name = st.selectbox("RM Name", ["Omkar", "Dhananjay", "Nagesh", "Prafull", "Sachin", "Forid", "Yuvraj"], index=0, key="user_rm_name")
                            location = st.selectbox("Location", ["Mumbai", "Kalyan", "Panvel", "Kolhapur"], index=0, key="user_rm_location")
                            financier = st.selectbox("Financier", ["Chola Micro", "Chola Prime"], index=0, key="user_rm_financier")
                            loan_type = st.selectbox("Loan Type", ["LAP", "Commercial Purchase", "Balance Transfer"], index=0, key="user_rm_loan_type")
                            application = st.selectbox("Application", ["Company", "Individual"], index=0, key="user_rm_application")
                            name = st.text_input("Name", value=customer["name"], key="user_rm_name_input")
                            mobile_number = st.text_input("Mobile Number", value=customer["mobile_1"], key="user_rm_mobile_number")
                            loan_amount = st.number_input("Loan Amount", min_value=0, value=customer.get("loan_amount", 0), key="user_rm_loan_amount")
                            if st.form_submit_button("Submit RM Details"):
                                customers_collection.update_one(
                                    {"customer_id": int(unique_id), "username": st.session_state.username},
                                    {"$set": {
                                        "rm_name": rm_name,
                                        "location_rm": location,
                                        "financier": financier,
                                        "loan_type": loan_type,
                                        "application": application,
                                        "loan_amount": loan_amount
                                    }}
                                )
                                st.success("RM details submitted successfully.")
                                log_update(st.session_state.username, {
                                    "customer_id": int(unique_id),
                                    "rm_name": rm_name,
                                    "location_rm": location,
                                    "financier": financier,
                                    "loan_type": loan_type,
                                    "application": application,
                                    "loan_amount": loan_amount
                                }, customer)
                                st.session_state.rm_customer = None

        if "Login" in tab_map:
            with user_tabs[tab_map["Login"]]:
                st.subheader("Login Tab")
                if 'customer_details' not in st.session_state:
                    st.session_state.customer_details = None

                with st.form("login_form_user"):
                    unique_id = st.selectbox("Select Customer ID", options=[c['customer_id'] for c in customers_collection.find({"username": st.session_state.username})], key="user_login_customer_id")
                    fetch_submitted = st.form_submit_button("Fetch Details")

                if fetch_submitted or st.session_state.customer_details:
                    if fetch_submitted:
                        st.session_state.customer_details = customers_collection.find_one({"customer_id": int(unique_id), "username": st.session_state.username})
                    customer = st.session_state.customer_details
                    if customer:
                        st.write("Customer Details:")
                        st.write(f"Name: {customer['name']}")
                        st.write(f"Location: {customer['location']}")
                        st.write(f"Contact Person: {customer['contact_person']}")
                        st.write(f"Mobile 1: {customer['mobile_1']}")
                        st.write(f"Mobile 2: {customer['mobile_2']}")

                        with st.form("login_form"):
                            date = st.date_input("Date", key="login_date_user")
                            amount = st.number_input("Amount", min_value=0.0, format="%.2f", key="login_amount_user")
                            if st.form_submit_button("Submit"):
                                login_data = {
                                    "login_date": date_to_str(date),
                                    "login_amount": amount
                                }
                                customers_collection.update_one(
                                    {"customer_id": int(unique_id), "username": st.session_state.username},
                                    {"$set": login_data}
                                )
                                st.success("Login data submitted successfully.")

        if "Sanction/Reject" in tab_map:
            with user_tabs[tab_map["Sanction/Reject"]]:
                st.subheader("Sanction/Reject Tab")
                if 'customer_details' not in st.session_state:
                    st.session_state.customer_details = None

                with st.form("sanction_reject_form_user"):
                    unique_id = st.selectbox("Select Customer ID", options=[c['customer_id'] for c in customers_collection.find({"username": st.session_state.username})], key="user_sanction_reject_customer_id")
                    fetch_submitted = st.form_submit_button("Fetch Details")

                if fetch_submitted or st.session_state.customer_details:
                    if fetch_submitted:
                        st.session_state.customer_details = customers_collection.find_one({"customer_id": int(unique_id), "username": st.session_state.username})
                    customer = st.session_state.customer_details
                    if customer:
                        st.write("Customer Details:")
                        st.write(f"Name: {customer['name']}")
                        st.write(f"Location: {customer['location']}")
                        st.write(f"Contact Person: {customer['contact_person']}")
                        st.write(f"Mobile 1: {customer['mobile_1']}")
                        st.write(f"Mobile 2: {customer['mobile_2']}")

                        with st.form("sanction_reject_form"):
                            date = st.date_input("Date", key="sanction_reject_date")
                            amount = st.number_input("Amount", min_value=0.0, format="%.2f", key="sanction_reject_amount")
                            status = st.selectbox("Customer Case Status", ["Rejected", "Sanctioned"], key="sanction_reject_status")
                            if st.form_submit_button("Submit"):
                                sanction_reject_data = {
                                    "sanction_date": date_to_str(date),
                                    "sanction_amount": amount,
                                    "sanction_status": status
                                }
                                customers_collection.update_one(
                                    {"customer_id": int(unique_id), "username": st.session_state.username},
                                    {"$set": sanction_reject_data}
                                )
                                st.success("Sanction/Reject data submitted successfully.")

        if "Disbursement 1/2" in tab_map:
            with user_tabs[tab_map["Disbursement 1/2"]]:
                st.subheader("Disbursement 1/2 Tab")
                if 'customer_details' not in st.session_state:
                    st.session_state.customer_details = None

                with st.form("disbursement_form_user"):
                    unique_id = st.selectbox("Select Customer ID", options=[c['customer_id'] for c in customers_collection.find({"username": st.session_state.username})], key="user_disbursement_customer_id")
                    fetch_submitted = st.form_submit_button("Fetch Details")

                if fetch_submitted or st.session_state.customer_details:
                    if fetch_submitted:
                        st.session_state.customer_details = customers_collection.find_one({"customer_id": int(unique_id), "username": st.session_state.username})
                    customer = st.session_state.customer_details
                    if customer:
                        st.write("Customer Details:")
                        st.write(f"Name: {customer['name']}")
                        st.write(f"Location: {customer['location']}")
                        st.write(f"Contact Person: {customer['contact_person']}")
                        st.write(f"Mobile 1: {customer['mobile_1']}")
                        st.write(f"Mobile 2: {customer['mobile_2']}")

                        with st.form("disbursement_form"):
                            date = st.date_input("Date", key="disbursement_date_user")
                            amount = st.number_input("Amount", min_value=0.0, format="%.2f", key="disbursement_amount_user")
                            offered_roi = st.number_input("Offered ROI (%)", min_value=0.0, format="%.2f", key="disbursement_offered_roi_user")
                            processing_fees = st.number_input("Processing Fees", min_value=0.0, format="%.2f", key="disbursement_processing_fees_user")
                            insurance_amount = st.number_input("Insurance Amount", min_value=0.0, format="%.2f", key="disbursement_insurance_amount_user")
                            if st.form_submit_button("Submit"):
                                disbursement_data = {
                                    "disbursement_date": date_to_str(date),
                                    "disbursement_amount": amount,
                                    "offered_roi": offered_roi,
                                    "processing_fees": processing_fees,
                                    "insurance_amount": insurance_amount
                                }
                                customers_collection.update_one(
                                    {"customer_id": int(unique_id), "username": st.session_state.username},
                                    {"$set": disbursement_data}
                                )
                                st.success("Disbursement data submitted successfully.")

        if "STATUS" in tab_map:
            with user_tabs[tab_map["STATUS"]]:
                st.subheader("STATUS")
                if 'status_customer' not in st.session_state:
                    st.session_state.status_customer = None

                with st.form("status_form_user"):
                    unique_id = st.selectbox("Select Customer ID", options=[c['customer_id'] for c in customers_collection.find({"username": st.session_state.username})], key="user_status_customer_id")
                    if st.form_submit_button("Fetch Details"):
                        if unique_id:
                            customer = customers_collection.find_one({"customer_id": int(unique_id), "username": st.session_state.username})
                            st.session_state.status_customer = customer

                if st.session_state.status_customer:
                    customer = st.session_state.status_customer
                    st.write("Customer Details:")
                    st.write(f"Product: {customer['product']}")
                    st.write(f"Type: {customer['customer_type']}")
                    st.write(f"Location: {customer['location']}")
                    st.write(f"Name: {customer['name']}")
                    st.write(f"Type of Entity: {customer['entity_type']}")
                    st.write(f"Contact Person: {customer['contact_person']}")
                    st.write(f"Mobile 1: {customer['mobile_1']}")
                    st.write(f"Mobile 2: {customer['mobile_2']}")
                    st.write(f"RM Name: {customer.get('rm_name', 'Not Assigned')}")
                    st.write(f"RM Location: {customer.get('location_rm', 'Not Assigned')}")
                    st.write(f"Financier: {customer.get('financier', 'Not Assigned')}")
                    st.write(f"Loan Type: {customer.get('loan_type', 'Not Assigned')}")
                    st.write(f"Application: {customer.get('application', 'Not Assigned')}")
                    st.write(f"Loan Amount: {customer.get('loan_amount', 'Not Assigned')}")
                    st.write(f"Login Date: {customer.get('login_date', 'Not Assigned')}")
                    st.write(f"Login Amount: {customer.get('login_amount', 'Not Assigned')}")
                    st.write(f"Sanction Date: {customer.get('sanction_date', 'Not Assigned')}")
                    st.write(f"Sanction Amount: {customer.get('sanction_amount', 'Not Assigned')}")
                    st.write(f"Sanction Status: {customer.get('sanction_status', 'Not Assigned')}")
                    st.write(f"Disbursement Date: {customer.get('disbursement_date', 'Not Assigned')}")
                    st.write(f"Disbursement Amount: {customer.get('disbursement_amount', 'Not Assigned')}")
                    st.write(f"Offered ROI: {customer.get('offered_roi', 'Not Assigned')}")
                    st.write(f"Processing Fees: {customer.get('processing_fees', 'Not Assigned')}")
                    st.write(f"Insurance Amount: {customer.get('insurance_amount', 'Not Assigned')}")
                    st.write(f"Other Queries: {customer.get('other_queries', 'Not Provided')}")

                    # Display PDFs and download links outside the form
                    for doc in ["signed_agreement", "pan", "cancelled_cheque", "gst", "shop_certificate", "partnership_deed", "incorporation_certificate"]:
                        if customer.get(doc):
                            st.write(f"{doc.replace('_', ' ').title()}:")
                            display_pdf(customer[doc])
                            st.download_button(
                                label=f"Download {doc.replace('_', ' ').title()}",
                                data=customer[doc],
                                file_name=f"{customer['name']}_{doc}.pdf",
                                mime="application/pdf"
                            )

                if st.button("Show All Data"):
                    df = pd.DataFrame(list(customers_collection.find({"username": st.session_state.username})))
                    st.dataframe(df)

        if "UPDATE" in tab_map:
            with user_tabs[tab_map["UPDATE"]]:
                st.subheader("Update Tab")

                # Always show the search box with the dropdown
                unique_ids = [c['customer_id'] for c in customers_collection.find({"username": st.session_state.username})]
                with st.form("fetch_update_form_user"):
                    unique_id = st.selectbox("Select Customer ID to Update", options=unique_ids, key="fetch_update_customer_id_user")
                    fetch_submitted = st.form_submit_button("Fetch Details")

                if fetch_submitted:
                    st.session_state.update_customer_id = unique_id

                if st.session_state.update_customer_id is not None:
                    customer = customers_collection.find_one({"customer_id": int(st.session_state.update_customer_id), "username": st.session_state.username})
                    if customer:
                        with st.form("update_customer_form_user"):
                            st.write("Channel Information")
                            product = st.selectbox("Product", ["Secured", "Unsecured"], index=["Secured", "Unsecured"].index(customer["product"]), key="user_update_product")
                            customer_type = st.selectbox("Type", ["Direct", "Referral", "Connector"], index=["Direct", "Referral", "Connector"].index(customer["customer_type"]), key="user_update_customer_type")
                            location = st.selectbox("Location", ["Mumbai", "Kalyan", "Panvel", "Kolhapur"], index=["Mumbai", "Kalyan", "Panvel", "Kolhapur"].index(customer["location"]), key="user_update_location")
                            name = st.text_input("Name", value=customer["name"], key="user_update_name")
                            entity_type = st.selectbox("Type of Entity", ["Individual", "Proprietor", "Partnership", "LLP", "Pvt Ltd"], index=["Individual", "Proprietor", "Partnership", "LLP", "Pvt Ltd"].index(customer["entity_type"]), key="user_update_entity_type")
                            contact_person = st.text_input("Contact Person", value=customer["contact_person"], key="user_update_contact_person")
                            mobile_1 = st.text_input("Mobile 1", value=customer["mobile_1"], max_chars=10, key="user_update_mobile_1")
                            mobile_2 = st.text_input("Mobile 2", value=customer["mobile_2"], max_chars=10, key="user_update_mobile_2")

                            signed_agreement = st.file_uploader("Upload Signed Agreement", type=["pdf"], key="user_update_signed_agreement")

                            pan = st.file_uploader("Upload PAN", type=["pdf"], key="user_update_pan")

                            cancelled_cheque = st.file_uploader("Upload Cancelled Cheque", type=["pdf"], key="user_update_cancelled_cheque")

                            gst = st.file_uploader("Upload GST", type=["pdf"], key="user_update_gst")

                            shop_certificate = st.file_uploader("Upload Shop Establishment Certificate", type=["pdf"], key="user_update_shop_certificate")

                            partnership_deed = st.file_uploader("Upload Partnership Deed", type=["pdf"], key="user_update_partnership_deed")

                            incorporation_certificate = st.file_uploader("Upload Certificate of Incorporation", type=["pdf"], key="user_update_incorporation_certificate")

                            other_queries = st.text_area("Other Queries", value=customer.get("other_queries", ''), key="user_update_other_queries")

                            st.write("Customer Information")
                            rm_name = st.selectbox("RM Name", ["Omkar", "Dhananjay", "Nagesh", "Prafull", "Sachin", "Forid", "Yuvraj"], index=0, key="user_update_rm_name")
                            location_rm = st.selectbox("Location", ["Mumbai", "Kalyan", "Panvel", "Kolhapur"], index=0, key="user_update_location_rm")
                            financier = st.selectbox("Financier", ["Chola Micro", "Chola Prime"], index=0, key="user_update_financier")
                            loan_type = st.selectbox("Loan Type", ["LAP", "Commercial Purchase", "Balance Transfer"], index=0, key="user_update_loan_type")
                            application = st.selectbox("Application", ["Company", "Individual"], index=0, key="user_update_application")
                            loan_amount = st.number_input("Loan Amount", min_value=0, value=customer.get("loan_amount", 0), key="user_update_loan_amount")

                            st.write("Login Information")
                            login_date = st.date_input("Login Date", key="user_update_login_date", value=datetime.strptime(customer.get("login_date", datetime.now().date().strftime('%Y-%m-%d')), '%Y-%m-%d').date())
                            login_amount = st.number_input("Login Amount", min_value=0.0, format="%.2f", key="user_update_login_amount", value=customer.get("login_amount", 0.0))

                            st.write("Sanction/Reject Information")
                            sanction_date = st.date_input("Sanction Date", key="user_update_sanction_date", value=datetime.strptime(customer.get("sanction_date", datetime.now().date().strftime('%Y-%m-%d')), '%Y-%m-%d').date())
                            sanction_amount = st.number_input("Sanction Amount", min_value=0.0, format="%.2f", key="user_update_sanction_amount", value=customer.get("sanction_amount", 0.0))
                            sanction_status = st.selectbox("Sanction Status", ["Rejected", "Sanctioned"], key="user_update_sanction_status", index=["Rejected", "Sanctioned"].index(customer.get("sanction_status", "Rejected")))

                            st.write("Disbursement Information")
                            disbursement_date = st.date_input("Disbursement Date", key="user_update_disbursement_date", value=datetime.strptime(customer.get("disbursement_date", datetime.now().date().strftime('%Y-%m-%d')), '%Y-%m-%d').date())
                            disbursement_amount = st.number_input("Disbursement Amount", min_value=0.0, format="%.2f", key="user_update_disbursement_amount", value=customer.get("disbursement_amount", 0.0))
                            offered_roi = st.number_input("Offered ROI (%)", min_value=0.0, format="%.2f", key="user_update_offered_roi", value=customer.get("offered_roi", 0.0))
                            processing_fees = st.number_input("Processing Fees", min_value=0.0, format="%.2f", key="user_update_processing_fees", value=customer.get("processing_fees", 0.0))
                            insurance_amount = st.number_input("Insurance Amount", min_value=0.0, format="%.2f", key="user_update_insurance_amount", value=customer.get("insurance_amount", 0.0))

                            update_submitted = st.form_submit_button("Update")
                            if update_submitted:
                                updated_customer_data = {
                                    "product": product,
                                    "customer_type": customer_type,
                                    "location": location,
                                    "name": name,
                                    "entity_type": entity_type,
                                    "contact_person": contact_person,
                                    "mobile_1": mobile_1,
                                    "mobile_2": mobile_2,
                                    "signed_agreement": file_to_binary(signed_agreement)[0] if signed_agreement else customer["signed_agreement"],
                                    "pan": file_to_binary(pan)[0] if pan else customer["pan"],
                                    "cancelled_cheque": file_to_binary(cancelled_cheque)[0] if cancelled_cheque else customer["cancelled_cheque"],
                                    "gst": file_to_binary(gst)[0] if gst else customer["gst"],
                                    "shop_certificate": file_to_binary(shop_certificate)[0] if shop_certificate else customer["shop_certificate"],
                                    "partnership_deed": file_to_binary(partnership_deed)[0] if partnership_deed else customer["partnership_deed"],
                                    "incorporation_certificate": file_to_binary(incorporation_certificate)[0] if incorporation_certificate else customer["incorporation_certificate"],
                                    "other_queries": other_queries,
                                    "rm_name": rm_name,
                                    "location_rm": location_rm,
                                    "financier": financier,
                                    "loan_type": loan_type,
                                    "application": application,
                                    "loan_amount": loan_amount,
                                    "login_date": date_to_str(login_date),
                                    "login_amount": login_amount,
                                    "sanction_date": date_to_str(sanction_date),
                                    "sanction_amount": sanction_amount,
                                    "sanction_status": sanction_status,
                                    "disbursement_date": date_to_str(disbursement_date),
                                    "disbursement_amount": disbursement_amount,
                                    "offered_roi": offered_roi,
                                    "processing_fees": processing_fees,
                                    "insurance_amount": insurance_amount
                                }
                                customers_collection.update_one({"customer_id": int(st.session_state.update_customer_id), "username": st.session_state.username}, {"$set": updated_customer_data})
                                st.success(f"You have successfully updated the customer data for Customer ID: {st.session_state.update_customer_id}")
                                log_update(st.session_state.username, updated_customer_data, customer)
                                st.session_state.update_customer_id = None  # Reset the session state after update

        if "DOWNLOAD" in tab_map:
            with user_tabs[tab_map["DOWNLOAD"]]:
                st.subheader("Download Tab")
                df = pd.DataFrame(list(customers_collection.find({"username": st.session_state.username})))
                towrite = io.BytesIO()
                df.to_excel(towrite, index=False, engine='xlsxwriter')
                towrite.seek(0)
                st.download_button(
                    label="Download customer data",
                    data=towrite,
                    file_name="customer_data.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )

    st.button("Logout", on_click=lambda: st.session_state.update({"user_logged_in": False, "username": ''}))
