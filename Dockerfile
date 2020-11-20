FROM ubuntu

RUN apt-get update
RUN apt-get install -y apt-utils vim curl apache2 apache2-utils
RUN apt-get -y install python3 libapache2-mod-wsgi-py3
RUN ln /usr/bin/python3 /usr/bin/python
RUN apt-get -y install python3-pip
RUN ln /usr/bin/pip3 /usr/bin/pip
RUN pip install --upgrade pip
RUN pip install django jsonfield numpy sklearn pandas requests bs4 lxml mysql-connector-python eml_parser tld libmagic dnspython

RUN mkdir /code
WORKDIR /code

COPY ./code/ /code/


RUN chmod 777 -R /code
RUN chmod 777 -R /var/log/apache2
RUN chmod 777 -R /var/run/apache2

COPY apache_8888.conf /etc/apache2/sites-available/000-default.conf
COPY ports.conf /etc/apache2/ports.conf
#COPY apache2.conf /etc/apache2/apache2.conf


RUN useradd -ms /bin/bash vault
RUN usermod -u 5602 vault
RUN groupmod -g 5187 vault
#RUN chown -R vault:vault /code
#RUN chown -R vault /code/
USER vault
RUN python /code/mysite/manage.py migrate



EXPOSE 8888
CMD ["apache2ctl", "-D", "FOREGROUND"]

#Create Docker Image: docker build -t registry.ased.io/mislam/uncc-email-header-classifier .
#RUN DOKCER Command: docker run -d -p 0.0.0.0:9999:8888/tcp d727b1c55085 
#note that, the container is listing at: 8888 and the request will be made at:9999, therefore 9999 will be forwarded to 8888



