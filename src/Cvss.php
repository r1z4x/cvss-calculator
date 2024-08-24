<?php

namespace Rootshell\CVSS;

use Rootshell\CVSS\Calculators\CVSS2Calculator;
use Rootshell\CVSS\Calculators\CVSS30Calculator;
use Rootshell\CVSS\Calculators\CVSS31Calculator;
use Rootshell\CVSS\Calculators\CVSS40Calculator;
use Rootshell\CVSS\Calculators\CVSSCalculator;
use Rootshell\CVSS\Exceptions\CVSSException;
use Rootshell\CVSS\Parsers\CVSS2Parser;
use Rootshell\CVSS\Parsers\CVSS31Parser;
use Rootshell\CVSS\Parsers\CVSS40Parser;
use Rootshell\CVSS\ValueObjects\CVSS23Object;
use Rootshell\CVSS\ValueObjects\CVSSObject;
use Rootshell\CVSS\ValueObjects\CVSSResults;

class CVSS
{
    private const V4_VALIDATION_REGEX = '/^CVSS:4.0\/AV:[NALP]\/AC:[LH]\/AT:[NP]\/PR:[NLH]\/UI:[NPA]\/VC:[NLH]\/VI:[NLH]\/VA:[NLH]\/SC:[NLH]\/SI:[NLH]\/SA:[NLH]/';
    private const V4_VALIDATION_REGEX_OPTIONALS = '/\/S:[^NP{1}|\s]|\/AU:[^YN{1}\s]|\/R:[^AIU{1}|\s]|\/V:[^CD|\s]|\/RE:[^LMH{1}|\s]|\/U:[^CGAR{1}|\s]|'
                                                    . '\/MAV:[^NALP{1}|\s]|\/MAC:[^LH{1}|\s]|\/MAT:[^NP{1}|\s]|\/MPR:[^NLH{1}|\s]|\/MUI:[^NPA{1}|\s]|'
                                                    . '\/MVC:[^HLN{1}|\s]|\/MVI:[^HLN{1}|\s]|\/MVA:[^HLN{1}|\s]|\/MSC:[^HLN{1}|\s]|\/MSI:[^SHLN{1}|\s]|\/MSA:[^SHLN{1}|\s]|'
                                                    . '\/CR:[^HML{1}|\s]|\/IR:[^HML{1}|\s]|\/AR:[^HML{1}|\s]|\/E:[^APU{1}|\s]/';
    private const V3_VALIDATION_REGEX = '/^CVSS:(3.1|3.0)\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]/';
    private const V2_VALIDATION_REGEX = '/AV:[LAN]\/AC:[HML]\/Au:[MSN]\/C:[NCP]\/I:[NCP]\/A:[NCP]/';

    public static function generateScores(string $vector): CVSSResults
    {
        if (!self::validateVector($vector)) {
            throw CVSSException::invalidVector();
        }

        $vectorVersion = self::getVectorVersion($vector);
        $calculator = self::buildCalculator($vectorVersion);

        $cvssObject = self::parseVector($vector, $vectorVersion);
        $cvssObject->baseScore = $calculator->calculateBaseScore($cvssObject);
        $cvssObject->temporalScore = $calculator->calculateTemporalScore($cvssObject);
        $cvssObject->environmentalScore = $calculator->calculateEnvironmentalScore($cvssObject);
        $cvssObject->severity = $calculator->calculateSeverity($cvssObject);

        return $cvssObject->getResults();
    }

    private static function parseVector(string $vector, string $version): CVSSObject
    {
        return match ($version) {
            CVSS23Object::VERSION_2 => CVSS2Parser::parseVector($vector),
            CVSS23Object::VERSION_30, CVSS23Object::VERSION_31 => CVSS31Parser::parseVector($vector),
            CVSS23Object::VERSION_40 => (new CVSS40Parser())->parseVector($vector),
        };
    }

    private static function buildCalculator(string $version): CVSSCalculator
    {
        return match ($version) {
            CVSS23Object::VERSION_2 => new CVSS2Calculator(),
            CVSS23Object::VERSION_30 => new CVSS30Calculator(),
            CVSS23Object::VERSION_31 => new CVSS31Calculator(),
            CVSS23Object::VERSION_40 => new CVSS40Calculator(),
            default => throw CVSSException::invalidVector(),
        };
    }

    private static function validateVector(string $vector): bool
    {
        return self::validCVSSFourVector($vector) || self::validCVSSThreeVector($vector) || self::validCVSSTwoVector($vector);
    }

    private static function validCVSSFourVector(string $vector): bool
    {
        if (!(bool)preg_match(self::V4_VALIDATION_REGEX, $vector, $matches)) {
            return false;
        }

        $optional = str_replace($matches[0], '', $vector);
        preg_match(self::V4_VALIDATION_REGEX_OPTIONALS, $optional, $matches);


        if ($optional && count($matches) > 0) {
            return false;
        }

        return true;
    }

    private static function validCVSSThreeVector(string $vector): bool
    {
        return (bool)preg_match(self::V3_VALIDATION_REGEX, $vector);
    }

    private static function validCVSSTwoVector(string $vector): bool
    {
        return (bool)preg_match(self::V2_VALIDATION_REGEX, $vector);
    }

    private static function getVectorVersion(string $vector): string
    {
        if (self::validCVSSTwoVector($vector)) {
            return CVSS23Object::VERSION_2;
        }

        return explode(':', explode('/', $vector)[0])[1];
    }
}
