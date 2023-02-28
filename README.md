# Guacamole Wrapper Package

[![pipeline status](https://gitlab.com/gacybercenter/open/guacamole-api-wrapper/badges/0.0.3/pipeline.svg)](https://gitlab.com/gacybercenter/open/guacamole-api-wrapper/-/commits/0.0.3)



This is a simple package that allows you to take advantage of all
currently available REST API calls within Apache Guacamole.

## Overview

This package creates a class named `session` allowing you to interact
with the REST API for Apache Guacamole in various ways. Full capabilities
include:

- **Generating and Deleting your REST API Auth token**
- **Users & UserGroups**  
    _list, create, update, delete_
- **Connection & ConnectionGroups**  
    _list, create, update, delete_
- **List Schema Info**  
    _list_
- **Sharing Profiles**  
    _list, create, delete_


### Work in Progress

- Code Enhancements
- CI/CD for auto deployment

## Install

```
pip install guacamole-api-wrapper
```

## Usage
The overall usage capabilities of this module are extensive, I would
recommend you leverage a good ide that can show all available functions
and arguments. I tried to ensure each function has a basic comment and
I have tested all functionality, but am always looking for ways to break
it in order to improve it.

**Initial Module Import:**
```
import guacamole
```

Defining session arguments and then list users

**syntax:**  
```
guacamole.session("https://{guacamole_base_url}", "{datasource}", "{username}", "{password}")
```

**example:**
```
session = guacamole.session("https://web.app/guacamole", "mysql", "guacadmin", "guacadmin")

session.list_users()
```