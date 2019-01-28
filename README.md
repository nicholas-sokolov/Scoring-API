# Scoring-API

## How to use

You can run server `api.py`

Args: 

[-p] [--port] (integer)

[-l] [--log] (string)

By default api run server on localhost:8080, without logfile.

## Field's type

`Filed` - Any type which has default checks (required, nullable)

`CharField` - String type value

`IntegerField` - Integer type value

`ArgumentsField` - Dictionary type value

`EmailField` - String that contains '@'

`PhoneField` - String or Number that has length = 11 and starts with '7'

`DateField` - String with format DD.MM.YYYY

`BirthDayField` - Date from which 70 years still haven't passed

`GenderField` - Integer which define gender sing (0 - UNKNOWN, 1 - MALE, 2 - FEMALE)

`ClientIDsField` - List or Tuple with integer IDs