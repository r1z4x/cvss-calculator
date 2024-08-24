<?php

declare(strict_types=1);

namespace Rootshell\CVSS\Test;

use PHPUnit\Framework\TestCase;
use Rootshell\CVSS\CVSS;
use Rootshell\CVSS\Exceptions\CVSSException;

class CVSSTest extends TestCase
{

    /**
     * @dataProvider vectorProvider
     */
    public function testGenerateScores(string $vector, float $baseScore, float $temporalScore, float $environmentScore): void
    {
        $result = CVSS::generateScores($vector);

        self::assertEquals($baseScore, $result->baseScore);
        self::assertEquals($temporalScore, $result->temporalScore);
        self::assertEquals($environmentScore, $result->environmentalScore);
    }

    public static function vectorProvider(): array
    {
        return [
            ['CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 7.3, 7.3, 7.3],
            ['CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 7.7, 7.7, 7.7],
            ['CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U', 5.2, 5.2, 5.2],
            ['CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N', 8.3, 8.3, 8.3],
            ['CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L', 8.1, 8.1, 8.1],
            ['CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N', 4.6, 4.6, 4.6],
            ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N', 5.1, 5.1, 5.1],
            ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N', 6.9, 6.9, 6.9],
            ['CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N', 5.9, 5.9, 5.9],
            ['CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H', 9.4, 9.4, 9.4],
            ['CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D', 8.3, 8.3, 8.3],
            ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A', 8.7, 8.7, 8.7],
            ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A', 10.0, 10.0, 10.0],
            ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A', 9.3, 9.3, 9.3],
            ['CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H', 6.4, 6.4, 6.4],
            ['CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P', 6.8, 6.8, 6.8],
            ['CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/MSI:S/S:P', 9.7, 9.7, 9.7],
            ['CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:H/VA:L/SC:L/SI:H/SA:L/E:P/CR:M/IR:L/AR:M/MAV:N/MAC:H/MAT:P/MPR:L/MUI:P/MVC:L/MVI:H/MVA:L/MSC:H/MSI:L/MSA:L/S:N/AU:N/R:U/V:D/RE:L/U:Green', 4.9, 4.9, 4.9],
            ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear', 6.9, 6.9, 6.9],
            ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear', 6.9, 6.9, 6.9],
            ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N', 0, 0, 0],


            ['CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.0, 8.0, 8.0],
            ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N/RL:U', 0.0, 0.0, 0.0],
            ['CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U', 5.0, 4.6, 4.6],
            ['CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N', 5.6, 5.6, 5.6],
            ['CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N/E:P', 5.6, 5.3, 5.3],
            ['CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N/E:P/RL:O', 5.6, 5.1, 5.1],
            ['CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N/E:P/RL:O/RC:U', 5.6, 4.7, 4.7],
            ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N/E:P/RL:T/RC:R/CR:L/IR:L/AR:L/MAV:L/MAC:L/MPR:H/MUI:R/MS:U/MC:H/MI:H/MA:H', 0.0, 0.0, 4.1],
            ['CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:R/CR:M/IR:L/AR:H/MAV:P/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:H/MA:H', 5.5, 4.6, 5.2],
            ['CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/CR:M/IR:M/AR:M/MAV:A/MAC:H/MUI:R/MS:U/MC:L/MI:L/MA:L', 8.0, 8.0, 4.3],
            ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:H/MA:H', 10.0, 8.1, 5.6],
            ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H', 10.0, 8.1, 5.6],

            ['CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.0, 8.0, 8.0],
            ['CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/CR:M/IR:M/AR:M/MAV:A/MAC:H/MUI:R/MS:U/MC:L/MI:L/MA:L', 8.0, 8.0, 4.3],
            ['CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/CR:M/IR:M/AR:M/MAV:A/MAC:H/MUI:R/MS:U/MC:L/MI:L/MA:L', 8.0, 8.0, 4.3],
            ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:H/MA:H', 10.0, 8.1, 5.6],
            ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H', 10.0, 8.1, 5.5],

            ['CVSS:2/AV:N/AC:L/Au:N/C:C/I:C/A:C', 10.0, 10.0, 10.0],
            ['CVSS:2/AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U/RL:OF/RC:UC', 10.0, 6.7, 6.7],
            ['CVSS:2/AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U/RL:OF/RC:UC/CDP:L/TD:L/CR:M/IR:M/AR:M', 10.0, 6.7, 1.7],
            ['CVSS:2/AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H', 7.8, 6.4, 9.1],
            ['CVSS:2/AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:L', 10.0, 8.3, 9.0],
            ['CVSS:2/AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:M', 6.2, 4.9, 7.4],
            ['AV:N/AC:L/Au:N/C:C/I:C/A:C', 10.0, 10.0, 10.0],
            ['AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U/RL:OF/RC:UC', 10.0, 6.7, 6.7],
            ['AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:M', 6.2, 4.9, 7.4],
        ];
    }

    /**
     * @dataProvider invalidVersionProvider
     */
    public function testInvalidCalculator(int|float $version): void
    {
        $this->expectExceptionCode(CVSSException::class);
        $this->expectExceptionMessage('The vector you have provided is invalid');
        $this->expectExceptionCode(403);

        $reflectCVSS = new \ReflectionClass(CVSS::class);
        $method = $reflectCVSS->getMethod('buildCalculator');
        $method->setAccessible(true);

        $cvs = new CVSS();
        $method->invokeArgs($cvs, ['version' => $version]);
    }

    public static function invalidVersionProvider(): array
    {
        return [
            [1],
            [3.2],
            [4],
            [5],
        ];
    }

    public static function vectorsProvider(): array
    {
        return [
            'Invalid CVSS4.0 - required options not passed' => [
                'vector' => 'CVSS:4.0/',
                'valid' => false
            ],
            'Invalid CVSS4.0 - only passed AV' => [
                'vector' => 'CVSS:4.0/AV:N/',
                'valid' => false
            ],
            'Invalid CVSS4.0 - only passed AV, but invalid' => [
                'vector' => 'CVSS:4.0/AV:R/',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV and AC' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV and AC, invalid AV' => [
                'vector' => 'CVSS:4.0/AV:R/AC:L',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, invalid AC' => [
                'vector' => 'CVSS:4.0/AV:N/AC:O',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, invalid AV, AC' => [
                'vector' => 'CVSS:4.0/AV:R/AC:O',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT, invalid AT' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:A',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT, PR' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT, PR, UI' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT, PR, UI, invalid PR' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:A/UI:N',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT, PR, UI, VC' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT, PR, UI, VC, invalid UI' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:L',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT, PR, UI, VC, invalid VC' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:A',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT, PR, UI, VC, VI' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT, PR, UI, VC, VI, invalid VI' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:O',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT, PR, UI, VC, VI, VA' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT, PR, UI, VC, VI, VA, invalid VA' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:B',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT, PR, UI, VC, VI, VA, SC' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT, PR, UI, VC, VI, VA, SC, invalid SC' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:Q',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT, PR, UI, VC, VI, VA, SC, SI' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N',
                'valid' => false
            ],
            'Invalid CVSS4.0 - passed AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, invalid SI' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:C',
                'valid' => false
            ],
            'Invalid CVSS4.0 without optionals, but invalid AC' => [
                'vector' => 'CVSS:4.0/AV:N/AC:T/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => false
            ],
            'Invalid CVSS4.0 without optionals, but invalid AT' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:K/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => false
            ],
            'Invalid CVSS4.0 without optionals, but invalid PR' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:K/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => false
            ],
            'Valid CVSS4.0 without optionals AV:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals AV:A' => [
                'vector' => 'CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals AV:L' => [
                'vector' => 'CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals AV:P' => [
                'vector' => 'CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Invalid CVSS4.0 - X passed as MAV' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAV:X/MAC:X/MAT:X/MPR:X/'
                                . '/UI:X/S:N/AU:N/R:A/V:D/RE:L/U:Clear',
                'valid' => false
            ],
            'Invalid CVSS4.0 - Q passed' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAV:Q',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional parameter' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAV:L',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals AC:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals AC:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals AT:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals AT:P' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals PR:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals PR:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals PR:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals UI:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals UI:P' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals UI:A' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals VC:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals VC:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals VC:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals VI:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals VI:P' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals VI:A' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals VA:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals VA:P' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals VA:A' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals SC:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals SC:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals SC:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:H/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals SI:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals SI:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:L/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals SI:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:H/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals SA:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals SA:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:L',
                'valid' => true
            ],
            'Valid CVSS4.0 without optionals SA:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:H',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional S:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/S:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional S:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/S:N',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional S:P' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/S:P',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional AU:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/AU:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional AU:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/AU:N',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional AU:P' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/AU:Y',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional R:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/R:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional R:A' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/R:A',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional R:U' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/R:U',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional R:I' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/R:I',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional V:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/V:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional V:D' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/V:D',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional V:C' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/V:C',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional RE:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/RE:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional RE:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/RE:L',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional RE:M' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/RE:M',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional RE:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/RE:H',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional U:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/RE:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional U:Clear' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/U:Clear',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional U:Green' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/U:Green',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional U:Amber' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/U:Amber',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional U:Red' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/U:Red',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MAV:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAV:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional MAV:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAX:N',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MAV:A' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAV:A',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MAV:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAV:L',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MAV:P' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAV:P',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MAC:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAC:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional MAC:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAC:L',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MAC:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAC:H',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MAT:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAT:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional MAT:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAT:N',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MAT:P' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAT:P',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MPR:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MPR:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional MPR:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MPR:N',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MPR:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MPR:L',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MPR:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MPR:H',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MUI:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MUI:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional MUI:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MUI:N',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MUI:P' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MUI:P',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MUI:A' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MUI:A',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MVC:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MVC:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional MVC:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MVC:N',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MVC:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MVC:L',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MVC:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MVC:H',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MVI:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MVI:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional MVI:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MVI:N',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MVI:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MVI:L',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MVI:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MVI:H',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MVA:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MVA:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional MVA:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MVA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MVA:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MVA:L',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MVA:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MVA:H',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MSC:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSC:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional MSC:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSC:N',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MSC:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSC:L',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MSC:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSC:H',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MSI:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSI:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional MSI:S' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSI:N',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MSI:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSI:N',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MSI:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSI:L',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MSI:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSI:H',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MSA:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSA:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional MSA:S' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MSA:N' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSA:N',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MSA:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSA:L',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MSA:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSA:H',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional CR:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/CR:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional CR:M' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/CR:M',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional CR:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/CR:L',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional CR:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional IR:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/IR:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional IR:M' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/IR:M',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional IR:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/IR:L',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional IR:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/IR:H',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional AR:X' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/AR:X',
                'valid' => false
            ],
            'Valid CVSS4.0 - with optional AR:M' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/AR:M',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional AR:L' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/AR:L',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional AR:H' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/AR:H',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional MAV, MAC, MAT, MPR, MUI, MVC, MVI, MVA, MSC, MSI, MSA' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MAV:N/MAC:L/MAT:N/MPR:L/'
                                . 'MUI:P/MVC:L/MVI:L/MVA:L/MSC:L/MSI:L/MSA:L',
                'valid' => true
            ],
            'Valid CVSS4.0 - with optional CR, IR, AR' => [
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/AR:H/CR:L/IR:L/AR:L',
                'valid' => true
            ],
            'Valid CVSS3.1' => [
                'vector' => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L',
                'valid' => true
            ],
            'Invalid CVSS3.1' => [
                'vector' => 'CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/',
                'valid' => false
            ],
            'Valid CVSS3.0' => [
                'vector' => 'CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N',
                'valid' => true,
            ],
            'Invalid CVSS3' => [
                'vector' => 'CVSS:3/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N',
                'valid' => false,
            ],
            'Valid CVSS2' => [
                'vector' => 'CVSS:2/AV:N/AC:L/Au:N/C:C/I:C/A:C',
                'valid' => true,
            ],
            'Invalid CVSS2' => [
                'vector' => 'CVSS:2/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N',
                'valid' => false,
            ],
            'Invalid CVSS' => [
                'vector' => 'CVSS:1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N',
                'valid' => false
            ]
        ];
    }

    /**
     * @dataProvider vectorsProvider
     */
    public function testValidation(string $vector, bool $valid): void
    {
        if (!$valid) {
            $this->expectException(CVSSException::class);
        }

        $result = CVSS::generateScores($vector);

        if ($valid) {
            $this->assertNotNull($result->baseScore);
            $this->assertNotNull($result->temporalScore);
            $this->assertNotNull($result->environmentalScore);
        }

    }
}
