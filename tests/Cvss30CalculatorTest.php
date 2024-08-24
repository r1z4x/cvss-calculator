<?php

declare(strict_types=1);

namespace Rootshell\CVSS\Test;

use PHPUnit\Framework\TestCase;
use Rootshell\CVSS\Calculators\CVSS30Calculator;
use Rootshell\CVSS\Calculators\CVSS31Calculator;
use Rootshell\CVSS\ValueObjects\CVSS23Object;
use Rootshell\CVSS\ValueObjects\CVSS4Object;

class CVSS30CalculatorTest  extends TestCase
{

    private CVSS30Calculator $calculator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->calculator = new CVSS30Calculator();
    }

    public function testCalculateModifiedImpactSubScoreInvalidCVSSObject(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Wrong CVSS object');

        $cvssObject = new CVSS4Object('','','','','','');
        $this->calculator->calculateModifiedImpactSubScore($cvssObject);
    }

    public function testCalculateModifiedImpact(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Wrong CVSS object');

        $cvssObject = new CVSS4Object('','','','','','');
        $this->calculator->calculateModifiedImpact($cvssObject);
    }
}