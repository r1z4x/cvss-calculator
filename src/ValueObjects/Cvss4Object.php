<?php

namespace Rootshell\CVSS\ValueObjects;

class CVSS4Object extends CVSSObject
{
    public function __construct(
        public string $eq1,
        public string $eq2,
        public string $eq3,
        public string $eq4,
        public string $eq5,
        public string $eq6,
        public float $av = 0.0,
        public float $pr = 0.0,
        public float $ui = 0.0,
        public float $ac = 0.0,
        public float $at = 0.0,
        public float $vc = 0.0,
        public float $vi = 0.0,
        public float $va = 0.0,
        public float $sc = 0.0,
        public float $si = 0.0,
        public float $sa = 0.0,
        public float $cr = 0.0,
        public float $ir = 0.0,
        public float $ar = 0.0,
        public float $e = 0.0,
    ) {
    }

    public function getMicroVector(): string
    {
        return $this->eq1 . $this->eq2 . $this->eq3 . $this->eq4 . $this->eq5 . $this->eq6;
    }

    public function hasZeroImpact(): bool
    {
        return $this->vc === 0.2 && $this->vi === 0.2 && $this->va === 0.2 && $this->sc === 0.3 && $this->si === 0.3 && $this->sa === 0.3;
    }

    public function getLowerVectors(): array
    {
        $vectors = [
            1 => ((int)$this->eq1 + 1) . $this->eq2 . $this->eq3 . $this->eq4 . $this->eq5 . $this->eq6,
            2 => $this->eq1 . ((int)$this->eq2 + 1) . $this->eq3 . $this->eq4 . $this->eq5 . $this->eq6,
            4 => $this->eq1 . $this->eq2 . $this->eq3 . ((int)$this->eq4 + 1) . $this->eq5 . $this->eq6,
            5 => $this->eq1 . $this->eq2 . $this->eq3 . $this->eq4 . ((int)$this->eq5 + 1) . $this->eq6,
        ];

        if ($this->eq3 === '0' && $this->eq6 === '0') {
            $vectors[3] = $this->eq1 . $this->eq2 . $this->eq3 . $this->eq4 . $this->eq5 . ((int)$this->eq6 + 1);
            $vectors[6] = $this->eq1 . $this->eq2 . ((int)$this->eq3 + 1) . $this->eq4 . $this->eq5 . $this->eq6;

            return $vectors;
        }

        $vectors[3] = match ($this->eq3 . $this->eq6) {
            '11', '01' => $this->eq1 . $this->eq2 . ((int)$this->eq3 + 1) . $this->eq4 . $this->eq5 . $this->eq6,
            '10' => $this->eq1 . $this->eq2 . $this->eq3 . $this->eq4 . $this->eq5 . ((int)$this->eq6 + 1),
            default => $this->eq1 . $this->eq2 . ((int)$this->eq3 + 1) . $this->eq4 . $this->eq5 . ((int)$this->eq6 + 1),
        };

        return $vectors;
    }

    public function validMaxVector(self $comparator): bool
    {
        return $this->getSeverityDistanceAV($comparator) >= 0.0 &&
            $this->getSeverityDistancePR($comparator) >= 0.0 &&
            $this->getSeverityDistanceUI($comparator) >= 0.0 &&
            $this->getSeverityDistanceAC($comparator) >= 0.0 &&
            $this->getSeverityDistanceAT($comparator) >= 0.0 &&
            $this->getSeverityDistanceVC($comparator) >= 0.0 &&
            $this->getSeverityDistanceVI($comparator) >= 0.0 &&
            $this->getSeverityDistanceVA($comparator) >= 0.0 &&
            $this->getSeverityDistanceSC($comparator) >= 0.0 &&
            $this->getSeverityDistanceSI($comparator) >= 0.0 &&
            $this->getSeverityDistanceSA($comparator) >= 0.0 &&
            $this->getSeverityDistanceCR($comparator) >= 0.0 &&
            $this->getSeverityDistanceIR($comparator) >= 0.0 &&
            $this->getSeverityDistanceAR($comparator) >= 0.0 &&
            $this->getSeverityDistanceE($comparator) >= 0.0;
    }

    public function getSeverityDistanceAV(self $comparator): float
    {
        return $comparator->av - $this->av;
    }

    public function getSeverityDistancePR(self $comparator): float
    {
        return $comparator->pr - $this->pr;
    }

    public function getSeverityDistanceUI(self $comparator): float
    {
        return $comparator->ui - $this->ui;
    }

    public function getSeverityDistanceAC(self $comparator): float
    {
        return $comparator->ac - $this->ac;
    }

    public function getSeverityDistanceAT(self $comparator): float
    {
        return $comparator->at - $this->at;
    }

    public function getSeverityDistanceVC(self $comparator): float
    {
        return $comparator->vc - $this->vc;
    }

    public function getSeverityDistanceVI(self $comparator): float
    {
        return $comparator->vi - $this->vi;
    }

    public function getSeverityDistanceVA(self $comparator): float
    {
        return $comparator->va - $this->va;
    }

    public function getSeverityDistanceSC(self $comparator): float
    {
        return $comparator->sc - $this->sc;
    }

    public function getSeverityDistanceSI(self $comparator): float
    {
        return $comparator->si - $this->si;
    }

    public function getSeverityDistanceSA(self $comparator): float
    {
        return $comparator->sa - $this->sa;
    }

    public function getSeverityDistanceCR(self $comparator): float
    {
        return $comparator->cr - $this->cr;
    }

    public function getSeverityDistanceIR(self $comparator): float
    {
        return $comparator->ir - $this->ir;
    }

    public function getSeverityDistanceAR(self $comparator): float
    {
        return $comparator->ar - $this->ar;
    }

    public function getSeverityDistanceE(self $comparator): float
    {
        return $comparator->e - $this->e;
    }
}
