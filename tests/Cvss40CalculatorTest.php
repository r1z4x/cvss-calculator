<?php

declare(strict_types=1);

namespace Rootshell\CVSS\Test;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use Rootshell\CVSS\Calculators\CVSS40Calculator;
use Rootshell\CVSS\ValueObjects\CVSS23Object;
use Rootshell\CVSS\ValueObjects\CVSS4Object;

class CVSS40CalculatorTest extends TestCase
{

    private CVSS40Calculator $calculator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->calculator = new CVSS40Calculator;
    }


    public function testInvalidCVSSObject(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Wrong CVSS object');

        $cvssObject = new CVSS23Object();

        $this->calculator->calculateBaseScore($cvssObject);
    }


    public function testInvalidMicroVector(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid initial value');

        $cvssObject = new CVSS4Object('2','8', '0', '1', '2', '3');

        $this->calculator->calculateBaseScore($cvssObject);
    }
    
    protected static function getMethod($name): ReflectionMethod
    {
        $class = new ReflectionClass(CVSS40Calculator::class);
        $method = $class->getMethod($name);
        $method->setAccessible(true);
        return $method;
    }

}