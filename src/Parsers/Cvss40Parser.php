<?php

namespace Rootshell\CVSS\Parsers;

use Rootshell\CVSS\Exceptions\CVSSException;
use Rootshell\CVSS\ValueObjects\CVSS23Object;
use Rootshell\CVSS\ValueObjects\CVSS4Object;

class CVSS40Parser
{
    private const NETWORK = 'N';
    private const ADJACENT = 'A';
    private const LOCAL = 'L';
    private const PHYSICAL = 'P';

    private const NOT_DEFINED = 'X';
    private const NONE = 'N';
    private const LOW = 'L';
    private const MEDIUM = 'M';
    private const HIGH = 'H';
    private const SAFETY = 'S';

    private const ATTACKED = 'A';
    private const POC = 'P';
    private const UNREPORTED = 'U';

    private const PRESENT = 'P';

    private const BASE_ATTACK_VECTOR = 'AV';
    private const BASE_ATTACK_COMPLEXITY = 'AC';

    private const ATTACK_REQUIREMENTS = 'AT';
    private const AVAILABILITY_REQUIREMENTS = 'AR';
    private const BASE_PRIVILEGES_REQUIRED = 'PR';
    private const BASE_USER_INTERACTION = 'UI';
    private const VULNERABLE_SYSTEM = 'VC';
    private const VULNERABLE_SYSTEM_INTEGRITY_IMPACT = 'VI';
    private const VULNERABLE_SYSTEM_AVAILABILITY_IMPACT = 'VA';
    private const MODIFIED_SUBSEQUENT_SYSTEM_INTEGRITY = 'MSI';
    private const MODIFIED_SUBSEQUENT_SYSTEM_AVAILABILITY = 'MSA';
    private const SUBSEQUENT_SYSTEM_CONFIDENTIALITY_IMPACT = 'SC';
    private const SUBSEQUENT_SYSTEM_INTEGRITY_IMPACT = 'SI';
    private const SUBSEQUENT_SYSTEM_AVAILABILITY_IMPACT = 'SA';
    private const EXPLOIT_MATURITY = 'E';
    private const CONFIDENTIALITY_REQUIREMENT = 'CR';
    private const INTEGRITY_REQUIREMENT = 'IR';

    public function parseVector(string $vector): CVSS4Object
    {
        $cr = $this->findOptionalValueInVector($vector, self::CONFIDENTIALITY_REQUIREMENT) ?? self::HIGH;
        $ir = $this->findOptionalValueInVector($vector, self::INTEGRITY_REQUIREMENT) ?? self::HIGH;
        $ar = $this->findOptionalValueInVector($vector, self::AVAILABILITY_REQUIREMENTS) ?? self::HIGH;
        $e = $this->findOptionalValueInVector($vector, self::EXPLOIT_MATURITY) ?? self::ATTACKED;

        return new CVSS4Object(
            eq1: $this->parseEQOne($vector),
            eq2: $this->parseEQTwo($vector),
            eq3: $this->parseEQThree($vector),
            eq4: $this->parseEQFour($vector),
            eq5: $this->parseEQFive($vector),
            eq6: $this->parseEQSix($vector),
            av: $this->parseAttackVector($this->findValueInVector($vector, self::BASE_ATTACK_VECTOR)),
            pr: $this->parsePrivilegesRequired($this->findValueInVector($vector, self::BASE_PRIVILEGES_REQUIRED)),
            ui: $this->parseUserInteraction($this->findValueInVector($vector, self::BASE_USER_INTERACTION)),
            ac: $this->parseAttackComplexity($this->findValueInVector($vector, self::BASE_ATTACK_COMPLEXITY)),
            at: $this->parseAttackRequirements($this->findValueInVector($vector, self::ATTACK_REQUIREMENTS)),
            vc: $this->parseVulnerableSystem($this->findValueInVector($vector, self::VULNERABLE_SYSTEM)),
            vi: $this->parseVulnerableSystemIntegrityImpact($this->findValueInVector($vector, self::VULNERABLE_SYSTEM_INTEGRITY_IMPACT)),
            va: $this->parseVulnerableSystemAvailabilityImpact($this->findValueInVector($vector, self::VULNERABLE_SYSTEM_AVAILABILITY_IMPACT)),
            sc: $this->parseSubsequentSystemConfidentialityImpact($this->findValueInVector($vector, self::SUBSEQUENT_SYSTEM_CONFIDENTIALITY_IMPACT)),
            si: $this->parseSubsequentSystemIntegrityImpact($this->findValueInVector($vector, self::SUBSEQUENT_SYSTEM_INTEGRITY_IMPACT)),
            sa: $this->parseSubsequentSystemAvailabilityImpact($this->findValueInVector($vector, self::SUBSEQUENT_SYSTEM_AVAILABILITY_IMPACT)),
            cr: $this->parseConfidentialityRequirement($cr),
            ir: $this->parseIntegrityRequirement($ir),
            ar: $this->parseAvailabilityRequirements($ar),
            e: $this->parseExploitMaturity($e),
        );
    }

    private function parseEQOne(string $vector): string
    {
        $av = $this->findValueInVector($vector, self::BASE_ATTACK_VECTOR);
        $pr = $this->findValueInVector($vector, self::BASE_PRIVILEGES_REQUIRED);
        $ui = $this->findValueInVector($vector, self::BASE_USER_INTERACTION);

        if ($av === self::NETWORK && $pr === self::NONE && $ui === self::NONE) {
            return '0';
        }

        if ($av === self::PHYSICAL || !($av === self::NETWORK || $pr === self::NONE || $ui === self::NONE)) {
            return '2';
        }

        return '1';
    }

    private function parseEQTwo(string $vector): string
    {
        $ac = $this->findValueInVector($vector, self::BASE_ATTACK_COMPLEXITY);
        $at = $this->findValueInVector($vector, self::ATTACK_REQUIREMENTS);

        if ($ac === self::LOW && $at === self::NONE) {
            return '0';
        }

        return '1';
    }

    private function parseEQThree(string $vector): string
    {
        $vc = $this->findValueInVector($vector, self::VULNERABLE_SYSTEM);
        $vi = $this->findValueInVector($vector, self::VULNERABLE_SYSTEM_INTEGRITY_IMPACT);
        $va = $this->findValueInVector($vector, self::VULNERABLE_SYSTEM_AVAILABILITY_IMPACT);

        if ($vc === self::HIGH && $vi === self::HIGH) {
            return '0';
        }

        if ($vc !== self::HIGH && $vi !== self::HIGH && $va !== self::HIGH) {
            return '2';
        }

        return '1';
    }

    private function parseEQFour(string $vector): string
    {
        $msi = $this->findOptionalValueInVector($vector, self::MODIFIED_SUBSEQUENT_SYSTEM_INTEGRITY) ?? self::NOT_DEFINED;
        $msa = $this->findOptionalValueInVector($vector, self::MODIFIED_SUBSEQUENT_SYSTEM_AVAILABILITY) ?? self::NOT_DEFINED;
        $sc = $this->findValueInVector($vector, self::SUBSEQUENT_SYSTEM_CONFIDENTIALITY_IMPACT);
        $si = $this->findValueInVector($vector, self::SUBSEQUENT_SYSTEM_INTEGRITY_IMPACT);
        $sa = $this->findValueInVector($vector, self::SUBSEQUENT_SYSTEM_AVAILABILITY_IMPACT);

        if ($msi === self::SAFETY || $msa === self::SAFETY) {
            return '0';
        }

        if ($sc === self::HIGH || $si === self::HIGH || $sa === self::HIGH) {
            return '1';
        }

        return '2';
    }

    private function parseEQFive(string $vector): string
    {
        $e = $this->findOptionalValueInVector($vector, self::EXPLOIT_MATURITY) ?? self::ATTACKED;

        if ($e === self::ATTACKED) {
            return '0';
        }

        if ($e === self::POC) {
            return '1';
        }

        return '2';
    }

    private function parseEQSix(string $vector): string
    {
        $cr = $this->findOptionalValueInVector($vector, self::CONFIDENTIALITY_REQUIREMENT) ?? self::HIGH;
        $vc = $this->findValueInVector($vector, self::VULNERABLE_SYSTEM);
        $ir = $this->findOptionalValueInVector($vector, self::INTEGRITY_REQUIREMENT) ?? self::HIGH;
        $vi = $this->findValueInVector($vector, self::VULNERABLE_SYSTEM_INTEGRITY_IMPACT);
        $ar = $this->findOptionalValueInVector($vector, self::AVAILABILITY_REQUIREMENTS) ?? self::HIGH;
        $va = $this->findValueInVector($vector, self::VULNERABLE_SYSTEM_AVAILABILITY_IMPACT);

        if (
            ($cr === self::HIGH && $vc === self::HIGH) ||
            ($ir === self::HIGH && $vi === self::HIGH) ||
            ($ar === self::HIGH && $va === self::HIGH)
        ) {
            return '0';
        }

        return '1';
    }

    private function parseAttackVector(string $value): float
    {
        return match ($value) {
            self::NETWORK => 0.0,
            self::ADJACENT => 0.1,
            self::LOCAL => 0.2,
            self::PHYSICAL => 0.3,
        };
    }

    private function parsePrivilegesRequired(string $value): float
    {
        return match ($value) {
            self::NONE => 0.0,
            self::LOW => 0.1,
            self::HIGH => 0.2,
        };
    }

    private function parseUserInteraction(string $value): float
    {
        return match ($value) {
            self::NONE => 0.0,
            self::POC => 0.1,
            self::ATTACKED => 0.2,
        };
    }

    private function parseAttackComplexity(string $value): float
    {
        return match ($value) {
            self::LOW => 0.0,
            self::HIGH => 0.1,
        };
    }

    private function parseAttackRequirements(string $value): float
    {
        return match ($value) {
            self::NONE => 0.0,
            self::PRESENT => 0.1,
        };
    }

    private function parseVulnerableSystem(string $value): float
    {
        return match ($value) {
            self::HIGH => 0.0,
            self::LOW => 0.1,
            self::NONE => 0.2,
        };
    }

    private function parseVulnerableSystemIntegrityImpact(string $value): float
    {
        return match ($value) {
            self::HIGH => 0.0,
            self::LOW => 0.1,
            self::NONE => 0.2,
        };
    }

    private function parseVulnerableSystemAvailabilityImpact(string $value): float
    {
        return match ($value) {
            self::HIGH => 0.0,
            self::LOW => 0.1,
            self::NONE => 0.2,
        };
    }

    private function parseSubsequentSystemConfidentialityImpact(string $value): float
    {
        return match ($value) {
            self::HIGH => 0.1,
            self::LOW => 0.2,
            self::NONE => 0.3,
        };
    }

    private function parseSubsequentSystemIntegrityImpact(string $value): float
    {
        return match ($value) {
            self::SAFETY => 0.0,
            self::HIGH => 0.1,
            self::LOW => 0.2,
            self::NONE => 0.3,
        };
    }

    private function parseSubsequentSystemAvailabilityImpact(string $value): float
    {
        return match ($value) {
            self::SAFETY => 0.0,
            self::HIGH => 0.1,
            self::LOW => 0.2,
            self::NONE => 0.3,
        };
    }

    private function parseConfidentialityRequirement(string $value): float
    {
        return match ($value) {
            self::HIGH => 0.0,
            self::MEDIUM => 0.1,
            self::LOW => 0.2,
        };
    }

    private function parseIntegrityRequirement(string $value): float
    {
        return match ($value) {
            self::HIGH => 0.0,
            self::MEDIUM => 0.1,
            self::LOW => 0.2,
        };
    }

    private function parseAvailabilityRequirements(string $value): float
    {
        return match ($value) {
            self::HIGH => 0.0,
            self::MEDIUM => 0.1,
            self::LOW => 0.2,
        };
    }

    private function parseExploitMaturity(string $value): float
    {
        return match ($value) {
            self::UNREPORTED => 0.2,
            self::POC => 0.1,
            self::ATTACKED => 0.0,
        };
    }

    private function findValueInVector(string $vector, string $section): string
    {
        $result = $this->findOptionalValueInVector($vector, $section);

        if (is_null($result)) {
            throw CVSSException::missingValue();
        }

        return $result;
    }

    private function findOptionalValueInVector(string $vector, string $section): ?string
    {
        $modifiedRegex = '/(?<=\/M' . $section . ':)(.*?)(?=\/|$)/';

        preg_match($modifiedRegex, '/' . $vector, $modifiedMatches);

        if (isset($modifiedMatches[0])) {
            return $modifiedMatches[0];
        }

        $regex = '/(?<=\/' . $section . ':)(.*?)(?=\/|$)/';
        preg_match($regex, '/' . $vector, $matches);

        return $matches[0] ?? null;
    }
}
