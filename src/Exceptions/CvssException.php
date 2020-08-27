<?php

declare(strict_types=1);

namespace Rootshell\Cvss\Exceptions;

use Exception;

class CvssException extends Exception
{
    public static function invalidValue(): self
    {
        return new static('Value could not be parsed', 403);
    }

    public static function missingValue(): self
    {
        return new static('Missing value', 403);
    }
    public static function invalidVector(): self
    {
        return new static('The vector you have provided is invalid', 403);
    }
}
