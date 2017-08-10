# django quickstart powershell

The purpose of this is to create a development environment to simply develop django apps from your windows machine based upon python3

## prerequisites

* Windows 10
* Docker for Windows 10
* Powershell

## installation and usage

```bash
git clone https://github.com/VOP556/powershell.git
cd powershell/django-quickstart
./start-django <your project path> <projectname>
cd <your project path>
docker-compose up -d --build
```

the projectpath will be created and in the end you will have 2 containers. One for your django app and one for your postgres database. The sourcecode will be mounted into the container from
```bash
<your project path>/src/<your project name>
```
you can live edit it there.

your data will persist on container recreation cause on EXIT call the db will be dumped to /srv/src/dump.json. if you do not want this, delete the file after it was created

