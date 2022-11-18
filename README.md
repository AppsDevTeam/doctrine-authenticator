# Doctrine Authenticator

- Allows you to use a Doctrine entity as a Nette identity.
- Use cookies instead of PHP sessions
- Regenerate token on each request to reduce the risk of token theft by brute force
- Save additional information like IP address and User-Agent header for better token theft detection
- Invalidate token on different User-Agent headers

## Install

```
composer require adt/doctrine-authenticator
```

## Usage

### 1) Neon configuration

```neon
services:
	security.user: App\Model\Security\SecurityUser
	security.userStorage: Nette\Bridges\SecurityHttp\CookieStorage
	security.authenticator:
		factory: App\Model\Security\Authenticator('14 days')
		setup:
			- setUserAgentCheck(true) # you can disable it for automatic tests for example
```

### 2) Create a Session entity extending ADT\DoctrineAuthenticator\StorageEntity

```php
<?php

declare(strict_types=1);

namespace App\Model\Entities;

use ADT\DoctrineAuthenticator\StorageEntity;
use App\Model\Entities\Attributes;
use Doctrine\ORM\Mapping as ORM;

/** 
 * @ORM\Entity 
 */
class Session extends StorageEntity
{
	use Attributes\Identifier;
}
```

### 3) Create a Identity entity implementing ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity

```php
<?php

namespace App\Model\Entities;

use ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity;
use ADT\DoctrineForms\Entity;
use App\Model\Entities\Attributes\Identifier;
use Doctrine\ORM\Mapping as ORM;

/** 
 * @ORM\Entity 
 */
class Identity implements DoctrineAuthenticatorIdentity, Entity
{
	use Identifier;

	/** @ORM\Column(type="string", unique=true) */
	protected string $email;

	/** @ORM\Column(type="string") */
	protected string $password;

	public function getRoles(): array
	{
		return [];
	}

	public function getEmail(): string
	{
		return $this->email;
	}

	public function setEmail(string $email): self
	{
		$this->email = $email;
		return $this;
	}

	public function getPassword(): string
	{
		return $this->password;
	}

	public function setPassword(string $password): self
	{
		$this->password = $password;
		return $this;
	}

	public function getAuthObjectId(): string
	{
		return (string) $this->getId();
	}
}
```

### 4) Create a SecurityUser service extending ADT\DoctrineAuthenticator\SecurityUser

```php
<?php

namespace App\Model\Security;

use App\Model\Entities\Identity;

/**
 * @method Identity getIdentity()
 */
class SecurityUser extends \ADT\DoctrineAuthenticator\SecurityUser
{

}
```

### 5) Create Authenticator extending ADT\DoctrineAuthenticator\DoctrineAuthenticator

```php
<?php

namespace App\Model\Security;

use ADT\DoctrineAuthenticator\DoctrineAuthenticator;
use App\Model\Entities\Identity;
use Doctrine\DBAL\Connection;
use Doctrine\ORM\Configuration;
use Doctrine\ORM\EntityManagerInterface;
use Nette\Bridges\SecurityHttp\CookieStorage;
use Nette\Http\Request;
use Nette\Security\AuthenticationException;
use Nette\Security\IIdentity;
use Nette\Security\Passwords;

class Authenticator extends DoctrineAuthenticator
{
	public function __construct(
		string $expiration,
		string $storageEntityClass,
		CookieStorage $cookieStorage,
		Connection $connection,
		Configuration $configuration,
		protected readonly EntityManagerInterface $em,
		protected readonly Request $httpRequest
	) {
		parent::__construct($expiration, $storageEntityClass, $cookieStorage, $connection, $configuration);
	}

	public function authenticate(string $user, string $password): IIdentity
	{
		/** @var Identity $identity */
		if (! $identity = $this->em->getRepository(Identity::class)->findOneBy(['email' => $user])) {
			throw new AuthenticationException('Identity not found!');
		}

		if (!(new Passwords())->verify($password, $identity->getPassword())) {
			throw new AuthenticationException('Incorrect password!');
		}

		return $identity;
	}

	public function getIdentity($id): IIdentity
	{
		return $this->em->getRepository(Identity::class)->find($id);
	}
}
```
