# Doctrine Authenticator

Allows you to use a Doctrine entity as a Nette identity.

## Example for CookieStorage

```neon
services:
	security.userStorage: ADT\DoctrineAuthenticator\CookieStorage
	security.authenticator: App\Model\Security\Authenticator('14 days')
```

```php
/**
 * @ORM\Entity
 */
class Session extends BaseEntity implements DoctrineAuthenticatorSession
{
	/** @ORM\ManyToOne(targetEntity="Identity", inversedBy="sessions") */
	protected Identity $identity;

	public function __construct(Identity $identity, string $token)
	{
		$this->identity = $identity;
		$this->token = $token;
	}

	public function getAuthEntity(): DoctrineAuthenticatorIdentityvi
	{
		return $this->identity;
	}
}
```

```php
/**
 * @ORM\Entity
 */
class Identity implements DoctrineAuthenticatorIdentity
{
	/** @ORM\OneToMany(targetEntity="Session", mappedBy="identity", cascade={"all"}) */
	protected $sessions;
	
	protected string $token;
	
	public function __construct()
	{
		$this->sessions = new ArrayCollection();
	}

	public function getAuthToken(): string
	{
		return $this->token;
	}
	
	public function setAuthToken(string $token): self
	{
		$this->token = $token;
		return $this;
	}
	
	public function logIn(string $token): self
	{
		$this->setAuthToken($token);
		$this->sessions->add(new Session($this, $token));
		return $this;
	}
	
	public function logOut(): void
	{
		/** @var Session $_session */
		foreach ($this->sessions->filter(fn(Session $session) => !$session->getValidUntil()) as $_session) {
			if ($_session->getToken() === $this->token) {
				$_session->setValidUntil(new DateTimeImmutable());
			}
		}
	}
}
```

```php
namespace App\Model\Security;

use ADT\DoctrineAuthenticator\DoctrineAuthenticator;
use Nette\Security as NS;

class Authenticator extends DoctrineAuthenticator
{
	public function authenticate(string $user, string $password): NS\IIdentity
	{
		if (! $identity = $this->em->getRepository(Identity::class)->findBy(['email' => $user, 'password' => (new NS\Passwords)->hash($password)])) {
			throw new NS\AuthenticationException('Identity not found');
		}
		
		$identity->logIn(Random::generate(32));

		return $identity;
	}
	
	protected function getEntity(IIdentity $identity): DoctrineAuthenticatorSession
	{
		return $this->em->getRepository(Session::class)->findOneBy(['token' => $identity->getId()]);
	}
}
```


## Example for SessionStorage

```neon
services:
	security.userStorage: Nette\Bridges\SecurityHttp\SessionStorage
	security.authenticator: App\Model\Security\Authenticator('14 days')
```

```php
/**
 * @ORM\Entity
 */
class User extends BaseEntity  implements IIdentity, UuidInterface, DoctrineAuthenticatorSession, DoctrineAuthenticatorIdentity
{
	public function getAuthEntity(): IIdentity
	{
		return $this;
	}

	public function getAuthToken(): string
	{
		return (string) $this->id;
	}
	
	public function setAuthToken(string $token): self
	{
		$this->token = $token;
		return $this;
	}
}
```

```php
namespace App\Model\Security;

use ADT\DoctrineAuthenticator\DoctrineAuthenticator;
use Nette\Security as NS;

class Authenticator extends DoctrineAuthenticator
{
	public function authenticate(string $user, string $password): NS\IIdentity
	{
		if (! $identity = $this->em->getRepository(Identity::class)->findBy(['email' => $user, 'password' => (new NS\Passwords)->hash($password)])) {
			throw new NS\AuthenticationException('Identity not found');
		}
		
		return $identity;
	}
}
```

## Best practice

Create your own security user to get code completion:

```neon
security.user: App\Model\Security\SecurityUser
```

```php

namespace App\Model\Security;

use Nette\Security\User;

/**
 * @method \App\Model\Entities\Identity getIdentity()
 * @method UserStorage getStorage()
 */
class SecurityUser extends User
{

}
```

Add creation timestamp (using [https://github.com/doctrine-extensions/DoctrineExtensions](https://github.com/doctrine-extensions/DoctrineExtensions/blob/main/doc/timestampable.md)):

```php

declare(strict_types=1);

namespace App\Model\Entities\Attributes;

use DateTimeImmutable;
use Gedmo\Mapping\Annotation as Gedmo;

trait CreatedAt
{
	/**
	 * @Gedmo\Timestampable(on="create")
	 * @ORM\Column(type="datetime_immutable")
	 */
	protected DateTimeImmutable $createdAt;


	public function getCreatedAt(): DateTimeImmutable
	{
		return $this->createdAt;
	}


	public function setCreatedAt(DateTimeImmutable $createdAt): self
	{
		$this->createdAt = $createdAt;
		return $this;
	}
}
```

Add valid until on log out and validate it on login:

Entities\Session:

```php
/** @ORM\Column(type="datetime_immutable", nullable=true) */
protected ?DateTimeImmutable $validUntil = null;

public function logOut(): void
{
	/** @var Session $_session */
	foreach ($this->sessions->filter(fn(Session $session) => !$session->getValidUntil()) as $_session) {
		if ($_session->getToken() === $this->token) {
			$_session->setValidUntil(new DateTimeImmutable());
		}
	}
}
```

SecurityUser:

```php 
public function __construct(IUserStorage $legacyStorage = null, IAuthenticator $authenticator = null, Authorizator $authorizator = null, UserStorage $storage = null)
{
	parent::__construct($legacyStorage, $authenticator, $authorizator, $storage);
	$this->onLoggedOut[] = function(SecurityUser $securityUser) {
		$securityUser->getIdentity()->logOut();
	};
}
```

Authenticator:

```php
protected function getEntity(IIdentity $identity): ?DoctrineAuthenticatorSession
{
	/** @var DoctrineAuthenticatorSession $entity */
	return $this->em->getRepository(Session::class)->findOneBy(['token' => $identity->getId(), 'validUntil' => NULL]);
}
```

