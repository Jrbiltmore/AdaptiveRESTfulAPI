import re
import string
import random

def generate_random_string(length=10, chars=string.ascii_letters + string.digits):
    """
    Generate a random string of specified length with characters from the given character set.
    :param length: The length of the random string (default is 10).
    :param chars: The character set to choose from (default is alphanumeric).
    :return: The generated random string.
    """
    return ''.join(random.choice(chars) for _ in range(length))

def is_valid_email(email):
    """
    Check if the provided email address is valid using a simple regular expression.
    :param email: The email address to validate.
    :return: True if the email address is valid, False otherwise.
    """
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

def sanitize_input(input_string):
    """
    Sanitize the input string by removing any potentially harmful characters.
    :param input_string: The input string to sanitize.
    :return: The sanitized input string.
    """
    sanitized_string = input_string.replace('<', '&lt;').replace('>', '&gt;')
    return sanitized_string

def secure_redirect(redirect_url):
    """
    Securely redirect by checking if the provided URL is safe and preventing open redirects.
    :param redirect_url: The URL to redirect to.
    :return: The secure redirect URL or None if the redirect is not allowed.
    """
    allowed_domains = ['example.com', 'yourdomain.com']  # Add your allowed domains here
    parsed_url = urlparse(redirect_url)

    if parsed_url.netloc in allowed_domains:
        return redirect_url

    return None
