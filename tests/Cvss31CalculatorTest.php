<?php

declare(strict_types=1);

namespace Rootshell\CVSS\Test;

use PHPUnit\Framework\TestCase;
use Rootshell\CVSS\Calculators\CVSS31Calculator;
use Rootshell\CVSS\ValueObjects\CVSS23Object;
use Rootshell\CVSS\ValueObjects\CVSS4Object;

class CVSS31CalculatorTest extends TestCase
{
    private CVSS31Calculator $calculator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->calculator = new CVSS31Calculator;
    }

    public function testBaseScoreUnchangedScope(): void
    {
        $cvssObject = new CVSS23Object;
        $cvssObject->confidentiality = 0.22;
        $cvssObject->integrity = 0.22;
        $cvssObject->availability = 0.22;
        $cvssObject->scope = 'U';
        $cvssObject->attackVector = 0.85;
        $cvssObject->attackComplexity = 0.44;
        $cvssObject->privilegesRequired = 0.62;
        $cvssObject->userInteraction = 0.62;

        $result = $this->calculator->calculateBaseScore($cvssObject);

        $this->assertEquals(4.6, $result);
    }

    public function testBaseScoreUnchangedScopeMax(): void
    {
        $cvssObject = new CVSS23Object;
        $cvssObject->confidentiality = 0.56;
        $cvssObject->integrity = 0.56;
        $cvssObject->availability = 0.56;
        $cvssObject->scope = 'U';
        $cvssObject->attackVector = 0.85;
        $cvssObject->attackComplexity = 0.77;
        $cvssObject->privilegesRequired = 0.85;
        $cvssObject->userInteraction = 0.85;

        $result = $this->calculator->calculateBaseScore($cvssObject);

        $this->assertEquals(9.8, $result);
    }

    public function testBaseScoreUnchangedScopeOverflow(): void
    {
        $cvssObject = new CVSS23Object;
        $cvssObject->confidentiality = 0.90;
        $cvssObject->integrity = 0.90;
        $cvssObject->availability = 0.90;
        $cvssObject->scope = 'U';
        $cvssObject->attackVector = 0.90;
        $cvssObject->attackComplexity = 0.90;
        $cvssObject->privilegesRequired = 0.90;
        $cvssObject->userInteraction = 0.90;

        $result = $this->calculator->calculateBaseScore($cvssObject);

        $this->assertEquals(10, $result);
    }

    public function testBaseScoreChangedScope(): void
    {
        $cvssObject = new CVSS23Object;
        $cvssObject->confidentiality = 0.22;
        $cvssObject->integrity = 0.22;
        $cvssObject->availability = 0.22;
        $cvssObject->scope = 'C';
        $cvssObject->attackVector = 0.85;
        $cvssObject->attackComplexity = 0.44;
        $cvssObject->privilegesRequired = 0.62;
        $cvssObject->userInteraction = 0.62;

        $result = $this->calculator->calculateBaseScore($cvssObject);

        $this->assertEquals(5.4, $result);
    }

    public function testBaseScoreChangedScopeMax(): void
    {
        $cvssObject = new CVSS23Object;
        $cvssObject->confidentiality = 0.56;
        $cvssObject->integrity = 0.56;
        $cvssObject->availability = 0.56;
        $cvssObject->scope = 'C';
        $cvssObject->attackVector = 0.85;
        $cvssObject->attackComplexity = 0.77;
        $cvssObject->privilegesRequired = 0.85;
        $cvssObject->userInteraction = 0.85;

        $result = $this->calculator->calculateBaseScore($cvssObject);

        $this->assertEquals(10.0, $result);
    }

    public function testInvalidCVSSObjectBaseScore(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Wrong CVSS object');

        $cvssObject = new CVSS4Object('','','','','','');
        $this->calculator->calculateBaseScore($cvssObject);
    }

    public function testImpactScore(): void
    {
        $cvssObject = new CVSS23Object;
        $cvssObject->confidentiality = 0.56;
        $cvssObject->integrity = 0.56;
        $cvssObject->availability = 0.56;
        $cvssObject->scope = 'C';
        $cvssObject->attackVector = 0.85;
        $cvssObject->attackComplexity = 0.44;
        $cvssObject->privilegesRequired = 0.62;
        $cvssObject->userInteraction = 0.62;

        $result = $this->calculator->calculateBaseScore($cvssObject);

        $this->assertEquals(0.9148160000000001, $cvssObject->impactSubScore);
        $this->assertEquals(6.0477304915445185, $cvssObject->impact);

    }

    public function testTemporalScore(): void
    {
        $cvssObject = new CVSS23Object;
        $cvssObject->baseScore = 4.6;
        $cvssObject->exploitCodeMaturity = 0.91;
        $cvssObject->remediationLevel = 0.95;
        $cvssObject->reportConfidence = 0.96;

        $result = $this->calculator->calculateTemporalScore($cvssObject);

        $this->assertEquals(3.9, $result);
    }

    public function testInvalidCVSSObjectTemporalScore(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Wrong CVSS object');

        $cvssObject = new CVSS4Object('','','','','','');
        $this->calculator->calculateTemporalScore($cvssObject);
    }

    public function testEnvironmentalScoreUnchangedScope(): void
    {
        $cvssObject = new CVSS23Object;
        $cvssObject->exploitCodeMaturity = 0.91;
        $cvssObject->remediationLevel = 0.95;
        $cvssObject->reportConfidence = 0.96;
        $cvssObject->confidentialityRequirement = 1;
        $cvssObject->integrityRequirement = 0.5;
        $cvssObject->availabilityRequirement = 1.5;
        $cvssObject->modifiedScope = 'U';
        $cvssObject->modifiedAttackVector = 0.2;
        $cvssObject->modifiedAttackComplexity = 0.44;
        $cvssObject->modifiedPrivilegesRequired = 0.68;
        $cvssObject->modifiedUserInteraction = 0.62;
        $cvssObject->modifiedConfidentiality = 0.22;
        $cvssObject->modifiedIntegrity = 0.56;
        $cvssObject->modifiedAvailability = 0.56;

        $result = $this->calculator->calculateEnvironmentalScore($cvssObject);
        $this->assertEquals(5.2, $result);
    }

    public function testEnvironmentalScoreUnchangedScopeMax(): void
    {
        $cvssObject = new CVSS23Object;
        $cvssObject->exploitCodeMaturity = 1;
        $cvssObject->remediationLevel = 1;
        $cvssObject->reportConfidence = 1;
        $cvssObject->confidentialityRequirement = 1.5;
        $cvssObject->integrityRequirement = 1.5;
        $cvssObject->availabilityRequirement = 1.5;
        $cvssObject->modifiedScope = 'U';
        $cvssObject->modifiedAttackVector = 0.85;
        $cvssObject->modifiedAttackComplexity = 0.77;
        $cvssObject->modifiedPrivilegesRequired = 0.85;
        $cvssObject->modifiedUserInteraction = 0.85;
        $cvssObject->modifiedConfidentiality = 0.56;
        $cvssObject->modifiedIntegrity = 0.56;
        $cvssObject->modifiedAvailability = 0.56;

        $result = $this->calculator->calculateEnvironmentalScore($cvssObject);
        $this->assertEquals(9.8, $result);
    }

    public function testEnvironmentalScoreUnchangedScopeOverflow(): void
    {
        $cvssObject = new CVSS23Object;
        $cvssObject->exploitCodeMaturity = 1;
        $cvssObject->remediationLevel = 1;
        $cvssObject->reportConfidence = 1;
        $cvssObject->confidentialityRequirement = 1.8;
        $cvssObject->integrityRequirement = 1.8;
        $cvssObject->availabilityRequirement = 1.8;
        $cvssObject->modifiedScope = 'U';
        $cvssObject->modifiedAttackVector = 0.9;
        $cvssObject->modifiedAttackComplexity = 0.87;
        $cvssObject->modifiedPrivilegesRequired = 0.95;
        $cvssObject->modifiedUserInteraction = 0.95;
        $cvssObject->modifiedConfidentiality = 0.66;
        $cvssObject->modifiedIntegrity = 0.66;
        $cvssObject->modifiedAvailability = 0.66;

        $result = $this->calculator->calculateEnvironmentalScore($cvssObject);
        $this->assertEquals(10, $result);
    }

    public function testEnvironmentalScoreChangedScope(): void
    {
        $cvssObject = new CVSS23Object;
        $cvssObject->exploitCodeMaturity = 0.91;
        $cvssObject->remediationLevel = 0.95;
        $cvssObject->reportConfidence = 0.96;
        $cvssObject->confidentialityRequirement = 1;
        $cvssObject->integrityRequirement = 0.5;
        $cvssObject->availabilityRequirement = 1.5;
        $cvssObject->modifiedScope = 'C';
        $cvssObject->modifiedAttackVector = 0.2;
        $cvssObject->modifiedAttackComplexity = 0.44;
        $cvssObject->modifiedPrivilegesRequired = 0.68;
        $cvssObject->modifiedUserInteraction = 0.62;
        $cvssObject->modifiedConfidentiality = 0.22;
        $cvssObject->modifiedIntegrity = 0.56;
        $cvssObject->modifiedAvailability = 0.56;

        $result = $this->calculator->calculateEnvironmentalScore($cvssObject);
        $this->assertEquals(5.9, $result);
    }

    public function testEnvironmentalScoreChangedScopeMax(): void
    {
        $cvssObject = new CVSS23Object;
        $cvssObject->exploitCodeMaturity = 1;
        $cvssObject->remediationLevel = 1;
        $cvssObject->reportConfidence = 1;
        $cvssObject->confidentialityRequirement = 1.5;
        $cvssObject->integrityRequirement = 1.5;
        $cvssObject->availabilityRequirement = 1.5;
        $cvssObject->modifiedScope = 'C';
        $cvssObject->modifiedAttackVector = 0.85;
        $cvssObject->modifiedAttackComplexity = 0.77;
        $cvssObject->modifiedPrivilegesRequired = 0.85;
        $cvssObject->modifiedUserInteraction = 0.85;
        $cvssObject->modifiedConfidentiality = 0.56;
        $cvssObject->modifiedIntegrity = 0.56;
        $cvssObject->modifiedAvailability = 0.56;

        $result = $this->calculator->calculateEnvironmentalScore($cvssObject);
        $this->assertEquals(10, $result);
    }

    public function testEnvironmentalScoreChangedScopeOverflow(): void
    {
        $cvssObject = new CVSS23Object;
        $cvssObject->exploitCodeMaturity = 1;
        $cvssObject->remediationLevel = 1;
        $cvssObject->reportConfidence = 1;
        $cvssObject->confidentialityRequirement = 1.8;
        $cvssObject->integrityRequirement = 1.8;
        $cvssObject->availabilityRequirement = 1.8;
        $cvssObject->modifiedScope = 'C';
        $cvssObject->modifiedAttackVector = 0.9;
        $cvssObject->modifiedAttackComplexity = 0.87;
        $cvssObject->modifiedPrivilegesRequired = 0.95;
        $cvssObject->modifiedUserInteraction = 0.95;
        $cvssObject->modifiedConfidentiality = 0.66;
        $cvssObject->modifiedIntegrity = 0.66;
        $cvssObject->modifiedAvailability = 0.66;

        $result = $this->calculator->calculateEnvironmentalScore($cvssObject);
        $this->assertEquals(10, $result);
    }

    public function testInvalidCVSSObjectEnvironmentalScore(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Wrong CVSS object');

        $cvssObject = new CVSS4Object('','','','','','');
        $this->calculator->calculateEnvironmentalScore($cvssObject);
    }

    public function testInvalidCVSSObjectCalculateModifiedImpactSubScore(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Wrong CVSS object');

        $cvssObject = new CVSS4Object('','','','','','');
        $this->calculator->calculateModifiedImpactSubScore($cvssObject);
    }

    public function testInvalidCVSSObjectCalculateModifiedImpact(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Wrong CVSS object');

        $cvssObject = new CVSS4Object('','','','','','');
        $this->calculator->calculateModifiedImpact($cvssObject);
    }
}
