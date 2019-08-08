# Laravel Passport Revoke
[![Build Status](https://travis-ci.org/jobilla/laravel-passport-revoke.svg?branch=master)](https://travis-ci.org/jobilla/laravel-passport-revoke)[![codecov](https://codecov.io/gh/jobilla/laravel-passport-revoke/branch/master/graph/badge.svg)](https://codecov.io/gh/jobilla/laravel-passport-revoke)

This package provides a single Artisan command for revoking a set of
active Laravel Passport tokens, to ease mass revocations. This can
be useful if you add or remove claims from the JWT and need every
user to have a newly issued token.

## Installation

Install the package using Composer.
```
composer require jobilla/passport-revoke
```

## Usage

Not passing any arguments to the command will revoke all active tokens:
```
php artisan passport:revoke
```

You may pass a token ID as the argument to revoke a single token:
```
php artisan passport:revoke 3
```

Or you may pass a `--user` option to revoke all active tokens for a given
user.

```
php artisan passport:revoke --user=27
```
