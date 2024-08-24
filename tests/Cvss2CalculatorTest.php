<?php

namespace Rootshell\CVSS\Test;

use PHPUnit\Framework\TestCase;
use Rootshell\CVSS\Calculators\CVSS2Calculator;
use Rootshell\CVSS\ValueObjects\CVSS23Object;
use Rootshell\CVSS\ValueObjects\CVSS4Object;

class CVSS2CalculatorTest extends TestCase
{

    private CVSS2Calculator $calculator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->calculator = new CVSS2Calculator;
    }


    /**
     * @dataProvider baseScoreProvider
     */
    public function testCalculateBaseScore(
        float $accessVector,
        float $accessComplexity,
        float $authentication,
        float $confidentiality,
        float $integrity,
        float $availability,
        float $expectedResult
    ): void {
        $cvssObject = new CVSS23Object;
        $cvssObject->accessVector = $accessVector;
        $cvssObject->accessComplexity = $accessComplexity;
        $cvssObject->authentication = $authentication;
        $cvssObject->confidentiality = $confidentiality;
        $cvssObject->integrity = $integrity;
        $cvssObject->availability = $availability;

        $result = $this->calculator->calculateBaseScore($cvssObject);
        self::assertEquals($expectedResult, $result);
    }

    public static function baseScoreProvider(): array
    {
        return [
            [1.00, 0.71, 0.704, 0.66, 0.66, 0.66, 10.0],
            [0.395, 0.35, 0.704, 0.66, 0.66, 0.66, 6.2],
            [0.395, 0.35, 0.704, 0, 0, 0, 0.0],
        ];
    }

    public function testInvalidCVSSObjectBaseScore(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Wrong CVSS object');

        $cvssObject = new CVSS4Object('','','','','','');
        $this->calculator->calculateBaseScore($cvssObject);
    }

    /**
     * @dataProvider temporalScoreProvider
     */
    public function testCalculateTemporalScore(
        float $baseScore,
        float $exploitability,
        float $remediationLevel,
        float $reportConfidence,
        float $expectedResult
    ): void {
        $cvssObject = new CVSS23Object;
        $cvssObject->baseScore = $baseScore;
        $cvssObject->exploitability = $exploitability;
        $cvssObject->remediationLevel = $remediationLevel;
        $cvssObject->reportConfidence = $reportConfidence;

        $result = $this->calculator->calculateTemporalScore($cvssObject);
        self::assertEquals($expectedResult, $result);
    }

    public static function temporalScoreProvider(): array
    {
        return [
            [10.0, 0.95, 0.87, 1.00, 8.3],
            [7.8, 0.95, 0.87, 1.00, 6.4],
            [6.2, 0.90, 0.87, 1.00, 4.9],
        ];
    }

    public function testInvalidCVSSObjectTemporalScore(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Wrong CVSS object');

        $cvssObject = new CVSS4Object('','','','','','');
        $this->calculator->calculateTemporalScore($cvssObject);
    }

    public function testCalculateEnvironmentalScore(): void
    {
        $cvssObject = new CVSS23Object;
        $cvssObject->accessVector = 1.00;
        $cvssObject->accessComplexity = 0.71;
        $cvssObject->authentication = 0.704;
        $cvssObject->confidentiality = 0.66;
        $cvssObject->integrity = 0.66;
        $cvssObject->availability = 0.66;
        $cvssObject->impact = 10.0;

        $cvssObject->baseScore = 10.0;
        $cvssObject->exploitability = 0.95;
        $cvssObject->remediationLevel = 0.87;
        $cvssObject->reportConfidence = 1.00;

        $cvssObject->collateralDamagePotential = 0.5;
        $cvssObject->targetDistribution = 1.0;
        $cvssObject->confidentialityRequirement = 1.0;
        $cvssObject->integrityRequirement = 1.0;
        $cvssObject->availabilityRequirement = 0.5;

        $result = $this->calculator->calculateEnvironmentalScore($cvssObject);
        self::assertEquals(9.0, $result);
    }

    public function testInvalidCVSSObjectEnvironmentalScore(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Wrong CVSS object');

        $cvssObject = new CVSS4Object('','','','','','');
        $this->calculator->calculateEnvironmentalScore($cvssObject);
    }
}