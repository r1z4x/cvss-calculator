<?php

namespace Rootshell\CVSS\Test;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use Rootshell\CVSS\Exceptions\CVSSException;
use Rootshell\CVSS\Parsers\CVSS2Parser;
use Rootshell\CVSS\ValueObjects\CVSS23Object;

class CVSS2ParserTest extends TestCase
{
    private CVSS2Parser $parser;

    protected function setUp(): void
    {
        parent::setUp();
        $this->parser = new CVSS2Parser();
    }

    /**
     * @dataProvider genericParseProvider
     */
    public function testGenericParseMethodsValid(string $methodName, ?string $metricValue, float $expectedResult): void
    {
        $method = self::getMethod($methodName);
        $result = $method->invokeArgs($this->parser, [$metricValue]);

        self::assertEquals($expectedResult, $result);
    }

    public static function genericParseProvider(): array
    {
        return [
            // Access Vectors
            'Access Vector Network' => ['parseAccessVector', 'N', 1.0],
            'Access Vector Adjacent' => ['parseAccessVector', 'A', 0.646],
            'Access Vector Local' => ['parseAccessVector', 'L', 0.395],
            // Access Complexity
            'Access Complexity Low ' => ['parseAccessComplexity', 'L', 0.71],
            'Access Complexity Medium' => ['parseAccessComplexity', 'M', 0.61],
            'Access Complexity High' => ['parseAccessComplexity', 'H', 0.35],
            // Authentication Complexity
            'Authentication Multiple ' => ['parseAuthentication', 'M', 0.45],
            'Authentication Single' => ['parseAuthentication', 'S', 0.56],
            'Authentication None' => ['parseAuthentication', 'N', 0.704],
            // Confidentiality Integrity Availability
            'Confidentiality Integrity Availability Complete' => ['parseConfidentialityIntegrityAvailabilityImpact', 'C', 0.660],
            'Confidentiality Integrity Availability Partial' => ['parseConfidentialityIntegrityAvailabilityImpact', 'P', 0.275],
            'Confidentiality Integrity Availability None' => ['parseConfidentialityIntegrityAvailabilityImpact', 'N', 0],
            // Exploitability
            'Exploitability Not Defined' => ['parseExploitability', 'ND', 1],
            'Exploitability High' => ['parseExploitability', 'H', 1],
            'Exploitability Functional' => ['parseExploitability', 'F', 0.95],
            'Exploitability Proof Of Concept' => ['parseExploitability', 'POC', 0.9],
            'Exploitability Unproven' => ['parseExploitability', 'U', 0.85],
            'Exploitability Code Maturity not provided' => ['parseExploitability', null, 1],
            // Remediation Level
            'Remediation Level Not Defined' => ['parseRemediationLevel', 'ND', 1],
            'Remediation Level Unavialable' => ['parseRemediationLevel', 'U', 1],
            'Remediation Level Workaround' => ['parseRemediationLevel', 'W', 0.95],
            'Remediation Level Temporary fix' => ['parseRemediationLevel', 'TF', 0.90],
            'Remediation Level Official fix' => ['parseRemediationLevel', 'OF', 0.87],
            'Remediation Level Not Provided' => ['parseRemediationLevel', null, 1],
            // Report Confidence
            'Report Confidence Unconfirmed' => ['parseReportConfidence', 'UC', 0.90],
            'Report Confidence Uncorroborated' => ['parseReportConfidence', 'UR', 0.95],
            'Report Confidence Confirmed' => ['parseReportConfidence', 'C', 1],
            'Report Confidence Not Defined' => ['parseReportConfidence', 'ND', 1],
            'Report Confidence Not Provided' => ['parseReportConfidence', null, 1],
            // Collateral Damage Potential
            'Collateral Damage Potential None' => ['parseCollateralDamagePotential', 'N', 0],
            'Collateral Damage Potential Low' => ['parseCollateralDamagePotential', 'L', 0.1],
            'Collateral Damage Potential Low-medium' => ['parseCollateralDamagePotential', 'LM', 0.3],
            'Collateral Damage Potential Medium-high' => ['parseCollateralDamagePotential', 'MH', 0.4],
            'Collateral Damage Potential High' => ['parseCollateralDamagePotential', 'H', 0.5],
            'Collateral Damage Potential Not Defined' => ['parseCollateralDamagePotential', 'ND', 0],
            'Collateral Damage Potential Not Provided' => ['parseCollateralDamagePotential', null, 0],
            // Target Distribution Potential
            'Target Distribution None' => ['parseTargetDistribution', 'N', 0],
            'Target Distribution Low' => ['parseTargetDistribution', 'L', 0.25],
            'Target Distribution Medium' => ['parseTargetDistribution', 'M', 0.75],
            'Target Distribution High' => ['parseTargetDistribution', 'H', 1.0],
            'Target Distribution Not Defined' => ['parseTargetDistribution', 'ND', 1],
            'Target Distribution Not Provided' => ['parseTargetDistribution', null, 1],
            // Confidentiality Integrity Availability Requirements
            'Confidentiality Integrity Availability Requirements Not Defined' => ['parseSecurityRequirements', 'ND', 1],
            'Confidentiality Integrity Availability Requirements Low' => ['parseSecurityRequirements', 'L', 0.5],
            'Confidentiality Integrity Availability Requirements Medium' => ['parseSecurityRequirements', 'M', 1],
            'Confidentiality Integrity Availability Requirements High' => ['parseSecurityRequirements', 'H', 1.51],
            'Confidentiality Integrity Availability Requirements Not Provided' => ['parseSecurityRequirements', null, 1],
        ];
    }

    /**
     * @dataProvider invalidParseProvider
     */
    public function testInvalidParseMethodsValid(string $methodName, ?string $metricValue): void
    {
        $method = self::getMethod($methodName);
        $this->expectException(CVSSException::class);
        $method->invokeArgs($this->parser, [$metricValue]);
    }

    public static function invalidParseProvider(): array
    {
        return [
            // Access Vectors
            'Access Vector' => ['parseAccessVector', 'G'],
            // Access Complexity
            'Access Complexity' => ['parseAccessComplexity', 'X'],
            // Authentication
            'Authentication' => ['parseAuthentication', 'T'],
            // Confidentiality Integrity Availability
            'Confidentiality Integrity Availability' => ['parseConfidentialityIntegrityAvailabilityImpact', 'B'],
        ];
    }

    public function testParseBaseValues(): void
    {
        $method = self::getMethod('parseBaseValues');
        $result = $method->invokeArgs($this->parser, ['CVSS:2/AV:N/AC:M/Au:M/C:C/I:P/A:N', new CVSS23Object]);

        self::assertEquals(1.0, $result->accessVector);
        self::assertEquals(0.61, $result->accessComplexity);
        self::assertEquals(0.45, $result->authentication);
        self::assertEquals(0.660, $result->confidentiality);
        self::assertEquals(0.275, $result->integrity);
        self::assertEquals(0, $result->availability);
    }

    public function testParseTemporalValues(): void
    {
        $method = self::getMethod('parseTemporalValues');
        $result = $method->invokeArgs($this->parser, ['CVSS:2/AV:N/AC:M/Au:M/C:C/I:P/A:N/E:POC/RL:OF/RC:C', new CVSS23Object]);

        self::assertEquals(0.9, $result->exploitability);
        self::assertEquals(0.87, $result->remediationLevel);
        self::assertEquals(1, $result->reportConfidence);
    }

    public function testParseEnvironmentalValuesFull(): void
    {
        $method = self::getMethod('parseEnvironmentalValues');
        $result = $method->invokeArgs(
            $this->parser,
            [
                'CVSS:2/AV:N/AC:M/Au:M/C:C/I:P/A:N/E:POC/RL:OF/RC:C/CDP:MH/TD:L/CR:ND/IR:L/AR:H',
                new CVSS23Object,
            ]
        );

        self::assertEquals(0.4, $result->collateralDamagePotential);
        self::assertEquals(0.25, $result->targetDistribution);
        self::assertEquals(1.0, $result->confidentialityRequirement);
        self::assertEquals(0.5, $result->integrityRequirement);
        self::assertEquals(1.51, $result->availabilityRequirement);
    }

    public function testParseVectorFull(): void
    {
        $result = $this->parser::parseVector('CVSS:2/AV:N/AC:M/Au:M/C:C/I:P/A:N/E:POC/RL:OF/RC:C/CDP:MH/TD:L/CR:ND/IR:L/AR:H');

        self::assertEquals(1.0, $result->accessVector);
        self::assertEquals(0.61, $result->accessComplexity);
        self::assertEquals(0.45, $result->authentication);
        self::assertEquals(0.660, $result->confidentiality);
        self::assertEquals(0.275, $result->integrity);
        self::assertEquals(0, $result->availability);

        self::assertEquals(0.9, $result->exploitability);
        self::assertEquals(0.87, $result->remediationLevel);
        self::assertEquals(1, $result->reportConfidence);

        self::assertEquals(0.4, $result->collateralDamagePotential);
        self::assertEquals(0.25, $result->targetDistribution);
        self::assertEquals(1.0, $result->confidentialityRequirement);
        self::assertEquals(0.5, $result->integrityRequirement);
        self::assertEquals(1.51, $result->availabilityRequirement);
    }

    public function testFindValueInVectorFail(): void
    {
        $this->expectException(CVSSException::class);

        $method = self::getMethod('findValueInVector');
        $method->invokeArgs(
            $this->parser,
            [
                'CVSS:2/AV:N/AC:M/Au:M/C:C/A:N',
                'I',
            ]
        );
    }

    protected static function getMethod($name): ReflectionMethod
    {
        $class = new ReflectionClass(CVSS2Parser::class);
        $method = $class->getMethod($name);
        $method->setAccessible(true);
        return $method;
    }
}