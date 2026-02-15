# Assignment 1 

### RSA Signatures - Task 2: Exploiting Textbook RSA Signatures

You are given the source code of a simple website that a professor has created
to automate annoying tasks such as grading. It also distributes quotes to
particularly good students. To prevent students from coming up with their own
grade, the website authenticates them with RSA signatures.  Since the professor
is quite lazy and does not want to be bothered by students, he/she provides
another API to sign any paperwork except grades.

Your task is to obtain a signed message stating you got a 12, so that you can
receive a quote (as in a CTF flag).  To this end, you can use the given API and the malleability
properties of plain, textbook RSA.

To get started with the task, you can host a local version on your own machine (see below).
Afterwards, you can attack a version of the website hosted [here](https://rsasig.syssec.dk).

## Running the Service Locally

With the given files, you can play around with the service and test your code
locally on your own computer.  Note that all secret data has been redacted from
the code and replaced with dummy values.

If you have installed Python 3, you can install the required packages in an
isolated virtual environment:
```
$ python -m venv venv               # (1) create a virtual environment in the directory `venv`
$ . ./venv/bin/activate             # (2) activate the virtual environment
$ pip install -r requirements.txt   # (3) install the required packages into the virtual environment
```
To run the service you then simply execute the following:
```
$ FLASK_APP=main flask run          # (4) run the application
```
The next time you want to run the service, you only need to repeat step (4)
(possibly after activating the virtual environment again Step (4)).

Alternatively, we also prepared a Docker container that you can use:
```
# docker build -t rsa-signatures .
# docker run -p 5000:80 rsa-signatures
```

In both cases, the application is reachable at <http://localhost:5000/>.
