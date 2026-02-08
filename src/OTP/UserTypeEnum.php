<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

enum UserTypeEnum
{
	case EMAIL;
	case PHONE;
	case USERNAME;
}
