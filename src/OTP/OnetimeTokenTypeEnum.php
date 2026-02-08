<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

enum OnetimeTokenTypeEnum: string implements OnetimeTokenType
{
	case LOGIN = 'login';
	case VERIFICATION = 'verification';
}
