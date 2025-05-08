# NIBM Exam Alerts

NIBM Exam Alerts is a web application that allows users to register for exam alerts based on their preferences. Users can receive notifications about upcoming exams that match their registered criteria.

## Features

- User registration and authentication
- Ability to register for exam alerts
- Notifications for new exams matching user criteria
- Update email and exam preferences
- View notification history

## Technologies Used

- Flask: A lightweight WSGI web application framework in Python.
- Firebase: For user authentication and data storage.
- APScheduler: For scheduling tasks.
- BeautifulSoup: For web scraping exam data.
- Requests: For making HTTP requests.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/milenek-x/nibmexamalerts.git
   cd nibmexamalerts
   ```

2. Create a virtual environment (optional but recommended):

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required packages:

   ```bash
   pip install -r requirements.txt
   ```

4. Set up your Firebase project and configure the necessary credentials.

5. Run the application:

   ```bash
   python app.py
   ```

6. Open your browser and go to `http://127.0.0.1:5000` to access the application.

## Usage

- Register for an account to start receiving exam alerts.
- Log in to manage your exam preferences and view notifications.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any suggestions or improvements.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.