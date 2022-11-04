# Doctrine Authenticator

Allows you to use a Doctrine entity as a Nette identity.

## Example for CookieStorage

```neon
services:
	security.userStorage: ADT\DoctrineAuthenticator\CookieStorage
	security.authenticator: App\Model\Security\Authenticator('14 days', 'App\Model\Entities\Session', 'token')
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

	public function getAuthEntity(): IIdentity
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
	
	protected ?string $token = null;
	
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
		$this->sessions->add(new Session($this, $token);
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
		if (! $identity = $this->em->getRepository(Profile::class)->findBy(['email' => $user, 'password' => (new NS\Passwords)->hash($password)])) {
			throw new NS\AuthenticationException('Identity not found');
		}
		
		$identity->setAuthToken(Random::generate(32));

		return $profile;
	}
}
```


## Example for SessionStorage

```neon
services:
	security.userStorage: Nette\Bridges\SecurityHttp\SessionStorage
	security.authenticator: App\Model\Security\Authenticator('14 days', 'App\Model\Entities\Identity', 'id')
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
		if (! $profile = $this->em->getRepository(Profile::class)->findBy(['email' => $user, 'password' => (new NS\Passwords)->hash($password)])) {
			throw new NS\AuthenticationException('User not found');
		}
		
		return $profile;
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
 */
class SecurityUser extends User
{

}
```

Add creation timestamp:

```php

declare(strict_types=1);

namespace App\Model\Entities\Attributes;

use DateTimeImmutable;
use Gedmo\Mapping\Annotation as Gedmo;

trait CreatedAt
{
	/**
	 * @var DateTimeImmutable
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

```
/**
 * @method \App\Model\Entity\User getIdentity()
 */
class SecurityUser extends User
{
	public function __construct(string $module, EntityManager $em, IUserStorage $legacyStorage = null, IAuthenticator $authenticator = null, Authorizator $authorizator = null, UserStorage $storage = null)
	{
		parent::__construct($legacyStorage, $authenticator, $authorizator, $storage);
		$this->em = $em;
	}
`
```

