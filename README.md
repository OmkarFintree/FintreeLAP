#🌳 Fintree Finance LAP Application
Welcome to the Fintree Finance LAP Application! This application helps manage customer data and disbursement details efficiently using Streamlit and MongoDB.

🚀 Features
User Registration & Authentication: Register new users and authenticate existing users.
Admin Panel: Manage customer data, update details, and control user permissions.
User Panel: Access to add, update, view customer details, and download data.
File Uploads: Upload documents like PAN, Signed Agreement, etc.
Data Export: Download user and customer data in Excel format.
🛠️ Technologies Used
Streamlit: For creating the web application.
MongoDB: For the database.
Python: As the programming language.
Pandas: For data manipulation.
Openpyxl & Xlsxwriter: For handling Excel files.
📦 Installation
Clone the Repository:

sh
Copy code
git clone https://github.com/yourusername/fintree-finance-lap.git
cd fintree-finance-lap
Create a Virtual Environment:

sh
Copy code
python -m venv env
source env/bin/activate  # On Windows, use `env\Scripts\activate`
Install Dependencies:

sh
Copy code
pip install -r requirements.txt
Run the Application:

sh
Copy code
streamlit run app.py
🗃️ MongoDB Setup
Install MongoDB:

Follow the installation guide from the official MongoDB website.
Start MongoDB Server:

sh
Copy code
mongod
Configure the Database:

Create a database named Fintree_Finance.
Create collections: users, admins, customers, permissions, update_logs, deleted_users.
📑 Usage
Admin Login:

Use the username omadmin and password ompass for the main admin login.
User Registration:

New users can register and will require admin permission to access tabs.
Managing Customers:

Add, update, view customer details, and upload required documents.
Data Export:

Download user and customer data in Excel format from the Download tab.
🎉 Enjoy!
Feel free to explore and use the Fintree Finance LAP Application to manage your customer data efficiently!

This README provide
