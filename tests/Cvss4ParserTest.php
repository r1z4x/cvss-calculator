<?php

namespace Rootshell\CVSS\Test;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use Rootshell\CVSS\Exceptions\CVSSException;
use Rootshell\CVSS\Parsers\CVSS40Parser;

class CVSS4ParserTest extends TestCase
{
    private CVSS40Parser $parser;
    protected function setUp(): void
    {
        parent::setUp();
        $this->parser = new CVSS40Parser;
    }

    /**
     * @dataProvider genericParseProvider
     */
    public function testGenericParseMethodsValid(string $methodName, string $value, float $expected): void
    {
        $method = self::getMethod($methodName);
        $result = $method->invokeArgs($this->parser, [$value]);

        self::assertEquals($expected, $result);
    }

    public static function genericParseProvider(): array
    {
        return [
            ['parseExploitMaturity', 'U', 0.2],
            ['parseExploitMaturity', 'P', 0.1],
            ['parseExploitMaturity', 'A', 0.0],

            ['parseAvailabilityRequirements', 'H', 0.0],
            ['parseAvailabilityRequirements', 'M', 0.1],
            ['parseAvailabilityRequirements', 'L', 0.2],

            ['parseIntegrityRequirement', 'H', 0.0],
            ['parseIntegrityRequirement', 'M', 0.1],
            ['parseIntegrityRequirement', 'L', 0.2],

            ['parseConfidentialityRequirement', 'H', 0.0],
            ['parseConfidentialityRequirement', 'M', 0.1],
            ['parseConfidentialityRequirement', 'L', 0.2],

            ['parseSubsequentSystemConfidentialityImpact', 'H', 0.1],
            ['parseSubsequentSystemConfidentialityImpact', 'L', 0.2],
            ['parseSubsequentSystemConfidentialityImpact', 'N', 0.3],

            ['parseVulnerableSystemAvailabilityImpact', 'H', 0.0],
            ['parseVulnerableSystemAvailabilityImpact', 'L', 0.1],
            ['parseVulnerableSystemAvailabilityImpact', 'N', 0.2],

            ['parseVulnerableSystemIntegrityImpact', 'H', 0.0],
            ['parseVulnerableSystemIntegrityImpact', 'L', 0.1],
            ['parseVulnerableSystemIntegrityImpact', 'N', 0.2],

            ['parseVulnerableSystem', 'H', 0.0],
            ['parseVulnerableSystem', 'L', 0.1],
            ['parseVulnerableSystem', 'N', 0.2],

            ['parseAttackRequirements', 'N', 0.0],
            ['parseAttackRequirements', 'P', 0.1],

            ['parseAttackComplexity', 'L', 0.0],
            ['parseAttackComplexity', 'H', 0.1],

            ['parseUserInteraction', 'N', 0.0],
            ['parseUserInteraction', 'P', 0.1],
            ['parseUserInteraction', 'A', 0.2],

            ['parsePrivilegesRequired', 'N', 0.0],
            ['parsePrivilegesRequired', 'L', 0.1],
            ['parsePrivilegesRequired', 'H', 0.2],

            ['parseAttackVector', 'N', 0.0],
            ['parseAttackVector', 'A', 0.1],
            ['parseAttackVector', 'L', 0.2],
            ['parseAttackVector', 'P', 0.3],

            ['parseSubsequentSystemIntegrityImpact', 'S', 0.0],
            ['parseSubsequentSystemIntegrityImpact', 'H', 0.1],
            ['parseSubsequentSystemIntegrityImpact', 'L', 0.2],
            ['parseSubsequentSystemIntegrityImpact', 'N', 0.3],

            ['parseSubsequentSystemAvailabilityImpact', 'S', 0.0],
            ['parseSubsequentSystemAvailabilityImpact', 'H', 0.1],
            ['parseSubsequentSystemAvailabilityImpact', 'L', 0.2],
            ['parseSubsequentSystemAvailabilityImpact', 'N', 0.3],
        ];
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
        $class = new ReflectionClass(CVSS40Parser::class);
        $method = $class->getMethod($name);
        $method->setAccessible(true);
        return $method;
    }

}