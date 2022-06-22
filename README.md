# Doctrine authenticator

Allows you to use a Doctrine entity as a Nette identity.

## Example

```php
namespace App\Model\Security;

use ADT\DoctrineAuthenticator\DoctrineAuthenticator;
use Nette\Security as NS;

class Authenticator extends DoctrineAuthenticator
{
	public function authenticate(string $user, string $password): NS\IIdentity
	{
		// TODO
	}
}
