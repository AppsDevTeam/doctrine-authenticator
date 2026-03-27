<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator;

use Nette\Security\AuthenticationException;

class TooManyLoginAttemptsException extends AuthenticationException
{
}
