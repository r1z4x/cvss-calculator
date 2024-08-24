<?php

declare(strict_types=1);

namespace Rootshell\CVSS\Test;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use Rootshell\CVSS\Exceptions\CVSSException;
use Rootshell\CVSS\Parsers\CVSS31Parser;
use Rootshell\CVSS\ValueObjects\CVSS23Object;

class CVSS31ParserTest extends TestCase
{
    private CVSS31Parser $parser;

    protected function setUp(): void
    {
        parent::setUp();
        $this->parser = new CVSS31Parser;
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
            // Attack Vectors
            'Attack Vector Network' => ['parseAttackVector', 'N', 0.85],
            'Attack Vector Adjacent' => ['parseAttackVector', 'A', 0.62],
            'Attack Vector Local' => ['parseAttackVector', 'L', 0.55],
            'Attack Vector Physical' => ['parseAttackVector', 'P', 0.2],
            // Attack Complexity
            'Attack Complexity Low ' => ['parseAttackComplexity', 'L', 0.77],
            'Attack Complexity High' => ['parseAttackComplexity', 'H', 0.44],
            // User Interaction
            'User Interaction none' => ['parseUserInteraction', 'N', 0.85],
            'User Interaction Required' => ['parseUserInteraction', 'R', 0.62],
            // Confidentiality Integrity Availability
            'Confidentiality Integrity Availability High' => ['parseConfidentialityIntegrityOrAvailability', 'H', 0.56],
            'Confidentiality Integrity Availability Low' => ['parseConfidentialityIntegrityOrAvailability', 'L', 0.22],
            'Confidentiality Integrity Availability None' => ['parseConfidentialityIntegrityOrAvailability', 'N', 0],
            // Exploit Code Maturity
            'Exploit Code Maturity Not Defined' => ['parseExploitCodeMaturity', 'X', 1],
            'Exploit Code Maturity High' => ['parseExploitCodeMaturity', 'H', 1],
            'Exploit Code Maturity Functional' => ['parseExploitCodeMaturity', 'F', 0.97],
            'Exploit Code Maturity Proof Of Concept' => ['parseExploitCodeMaturity', 'P', 0.94],
            'Exploit Code Maturity Unproven' => ['parseExploitCodeMaturity', 'U', 0.91],
            'Exploit Code Maturity not provided' => ['parseExploitCodeMaturity', null, 1],
            // Remediation Level
            'Remediation Level Not Defined' => ['parseRemediationLevel', 'X', 1],
            'Remediation Level Unavialable' => ['parseRemediationLevel', 'U', 1],
            'Remediation Level Workaround' => ['parseRemediationLevel', 'W', 0.97],
            'Remediation Level Temporary fix' => ['parseRemediationLevel', 'T', 0.96],
            'Remediation Level Official fix' => ['parseRemediationLevel', 'O', 0.95],
            'Remediation Level Not Provided' => ['parseRemediationLevel', null, 1],
            // Report Confidence
            'Report Confidence Not Defined' => ['parseReportConfidence', 'X', 1],
            'Report Confidence Confirmed' => ['parseReportConfidence', 'C', 1],
            'Report Confidence Resonable' => ['parseReportConfidence', 'R', 0.96],
            'Report Confidence Unknown' => ['parseReportConfidence', 'U', 0.92],
            'Report Confidence Not Provided' => ['parseReportConfidence', null, 1],
            // Confidentiality Integrity Availability Requirements
            'Confidentiality Integrity Availability Requirements Not Defined' => ['parseConfidentialityIntegrityOrAvailabilityRequirements', 'X', 1],
            'Confidentiality Integrity Availability Requirements Low' => ['parseConfidentialityIntegrityOrAvailabilityRequirements', 'L', 0.5],
            'Confidentiality Integrity Availability Requirements Medium' => ['parseConfidentialityIntegrityOrAvailabilityRequirements', 'M', 1],
            'Confidentiality Integrity Availability Requirements High' => ['parseConfidentialityIntegrityOrAvailabilityRequirements', 'H', 1.5],
            'Confidentiality Integrity Availability Requirements Not Provided' => ['parseConfidentialityIntegrityOrAvailabilityRequirements', null, 1],
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
            // Attack Vectors
            'Attack Vector' => ['parseAttackVector', 'G', 0.85],
            // Attack Complexity
            'Attack Complexity ' => ['parseAttackComplexity', 'X', 0.77],
            // User Interaction
            'User Interaction' => ['parseUserInteraction', 'T', 0.85],
            // Confidentiality Integrity Availability
            'Confidentiality Integrity Availability' => ['parseConfidentialityIntegrityOrAvailability', 'B'],
        ];
    }

    public function testInvalidPrivilegesRequired(): void
    {
        $this->expectException(CVSSException::class);
        $method = self::getMethod('parsePrivilegesRequired');
        $method->invokeArgs($this->parser, ['R', 'U']);
    }

    /**
     * @dataProvider scopedParseProvider
     */
    public function testScopedParseMethodsValid(string $methodName, ?string $metricValue, string $scope, float $expectedResult): void
    {
        $method = self::getMethod($methodName);
        $result = $method->invokeArgs($this->parser, [$metricValue, $scope]);

        self::assertEquals($expectedResult, $result);
    }

    public static function scopedParseProvider(): array
    {
        return [
            'Privileges Required None (Unchanged)' => ['parsePrivilegesRequired', 'N', 'U', 0.85],
            'Privileges Required None (Changed)' => ['parsePrivilegesRequired', 'N', 'C', 0.85],
            'Privileges Required Low (Unchanged)' => ['parsePrivilegesRequired', 'L', 'U', 0.62],
            'Privileges Required Low (Changed)' => ['parsePrivilegesRequired', 'L', 'C', 0.68],
            'Privileges Required High (Unchanged)' => ['parsePrivilegesRequired', 'H', 'U', 0.27],
            'Privileges Required High (Changed)' => ['parsePrivilegesRequired', 'H', 'C', 0.5],
        ];
    }

    public function testParseBaseValues(): void
    {
        $method = self::getMethod('parseBaseValues');
        $result = $method->invokeArgs($this->parser, ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N', new CVSS23Object]);

        self::assertEquals(0.85, $result->attackVector);
        self::assertEquals(0.44, $result->attackComplexity);
        self::assertEquals(0.85, $result->privilegesRequired);
        self::assertEquals(0.85, $result->userInteraction);
        self::assertEquals('U', $result->scope);
        self::assertEquals(0.56, $result->confidentiality);
        self::assertEquals(0.22, $result->integrity);
        self::assertEquals(0, $result->availability);
    }

    public function testParseTemporalValues(): void
    {
        $method = self::getMethod('parseTemporalValues');
        $result = $method->invokeArgs($this->parser, ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:T/RC:C', new CVSS23Object]);

        self::assertEquals(1, $result->exploitCodeMaturity);
        self::assertEquals(0.96, $result->remediationLevel);
        self::assertEquals(1, $result->reportConfidence);
    }

    public function testParseEnvironmentalValuesFull(): void
    {
        $method = self::getMethod('parseEnvironmentalValues');
        $result = $method->invokeArgs(
            $this->parser,
            [
                'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:T/RC:C/CR:M/IR:L/AR:H/MAV:A/MAC:L/MPR:N/MUI:R/MS:C/MC:H/MI:L/MA:N',
                new CVSS23Object,
            ]
        );

        self::assertEquals(1, $result->confidentialityRequirement);
        self::assertEquals(0.5, $result->integrityRequirement);
        self::assertEquals(1.5, $result->availabilityRequirement);
        self::assertEquals(0.62, $result->modifiedAttackVector);
        self::assertEquals(0.77, $result->modifiedAttackComplexity);
        self::assertEquals(0.85, $result->modifiedPrivilegesRequired);
        self::assertEquals(0.62, $result->modifiedUserInteraction);
        self::assertEquals('C', $result->modifiedScope);
        self::assertEquals(0.56, $result->modifiedConfidentiality);
        self::assertEquals(0.22, $result->modifiedIntegrity);
        self::assertEquals(0, $result->modifiedAvailability);
    }

    public function testParseVectorFull(): void
    {
        $result = CVSS31Parser::parseVector('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:T/RC:C/CR:M/IR:L/AR:H/MAV:A/MAC:L/MPR:N/MUI:R/MS:C/MC:H/MI:L/MA:N');

        self::assertEquals(0.85, $result->attackVector);
        self::assertEquals(0.44, $result->attackComplexity);
        self::assertEquals(0.85, $result->privilegesRequired);
        self::assertEquals(0.85, $result->userInteraction);
        self::assertEquals('U', $result->scope);
        self::assertEquals(0.56, $result->confidentiality);
        self::assertEquals(0.56, $result->integrity);
        self::assertEquals(0.56, $result->availability);

        self::assertEquals(1, $result->exploitCodeMaturity);
        self::assertEquals(0.96, $result->remediationLevel);
        self::assertEquals(1, $result->reportConfidence);

        self::assertEquals(1, $result->confidentialityRequirement);
        self::assertEquals(0.5, $result->integrityRequirement);
        self::assertEquals(1.5, $result->availabilityRequirement);
        self::assertEquals(0.62, $result->modifiedAttackVector);
        self::assertEquals(0.77, $result->modifiedAttackComplexity);
        self::assertEquals(0.85, $result->modifiedPrivilegesRequired);
        self::assertEquals(0.62, $result->modifiedUserInteraction);
        self::assertEquals('C', $result->modifiedScope);
        self::assertEquals(0.56, $result->modifiedConfidentiality);
        self::assertEquals(0.22, $result->modifiedIntegrity);
        self::assertEquals(0, $result->modifiedAvailability);
    }

    public function testFindValueInVectorFail(): void
    {
        $this->expectException(CVSSException::class);

        $method = self::getMethod('findValueInVector');
        $method->invokeArgs(
            $this->parser,
            [
                'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H',
                'I',
            ]
        );
    }

    protected static function getMethod($name): ReflectionMethod
    {
        $class = new ReflectionClass(CVSS31Parser::class);
        $method = $class->getMethod($name);
        $method->setAccessible(true);
        return $method;
    }
}
