# django-rest-api
# otp_based_authentication
Django rest framework project for otp based authentication


## Technologies used
* DRF: A powerful and flexible toolkit for building Web APIs


## Installation
* If you wish to run your own build, first ensure you have python globally installed in your computer. If not, you can get python [here](https://www.python.org").
* After doing this, confirm that you have installed virtualenv globally as well. If not, run this:
    ```bash
        $ pip install virtualenv
    ```
* Then, Git clone this repo to your PC
    ```bash
        $ git clone https://github.com/gitgik/django-rest-api.git
    ```

* #### Dependencies
    1. Cd into your the cloned repo as such:
        ```bash
            $ cd django-rest-api
        ```
    2. Create and fire up your virtual environment:
        ```bash
            $ virtualenv  venv -p python3
            $ source venv/bin/activate
        ```
    3. Install the dependencies needed to run the app:
        ```bash
            $ pip install -r requirements.txt
        ```
    4. Make those migrations work
        ```bash
            $ python manage.py makemigrations
            $ python manage.py migrate
        ```

* #### Run It
    Fire up the server using this one simple command:
    ```bash
        $ python manage.py runserver
    ```
    You can now access the file api service on your browser by using
    ```
        http://localhost:8000/user/
    ```
  
## Postman collection
[click here](https://documenter.getpostman.com/view/25481132/2s9YymFPR1).

## .evn file
sample .env file
 ```
DATABASE_PASSWORD=test
DATABASE_USER=postgres
DATABASE_NAME=saga_tech
TW_ACCOUNT_SID=ACbb40adshjdbaf4eeec551a51de3
TW_AUTH_TOKEN=b4f5952qfwjhuysavuyvf264
TW_PHONE_NUMBER=+15035632601 ```
