package version

import "testing"

func TestParse(t *testing.T) {
	for _, s := range []string{"1.12.6", "v1.12.6", "1.35.3-rc.1", "v2026.6.1", "1.2"} {
		if _, err := Parse(s); err != nil {
			t.Errorf("Parse(%q): %v", s, err)
		}
	}
	for _, s := range []string{"", "latest", "main", "v", "1.x.3", "sha256:abc"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) should fail", s)
		}
	}
	v, _ := Parse("v1.35.3-rc.1")
	if v.Major != 1 || v.Minor != 35 || v.Patch != 3 || v.Pre != "rc.1" {
		t.Errorf("Parse = %+v", v)
	}
	if v.String() != "1.35.3-rc.1" {
		t.Errorf("String = %q", v.String())
	}
}

func TestCompare(t *testing.T) {
	order := []string{"1.12.6", "1.13.0-rc.1", "1.13.0", "1.13.10", "1.14.5", "2.0.0"}
	for i := 0; i+1 < len(order); i++ {
		a, b := MustParse(order[i]), MustParse(order[i+1])
		if Compare(a, b) >= 0 || Compare(b, a) <= 0 {
			t.Errorf("%s should sort before %s", order[i], order[i+1])
		}
	}
	if Compare(MustParse("v1.2.3"), MustParse("1.2.3")) != 0 {
		t.Error("leading v must not matter")
	}
}

func TestGap(t *testing.T) {
	cases := []struct {
		from, to string
		want     Delta
		label    string
	}{
		{"1.12.6", "1.14.5", Delta{Minor: 2}, "2 minor"},
		{"1.35.3", "1.37.2", Delta{Minor: 2}, "2 minor"},
		{"1.5.0", "1.13.1", Delta{Minor: 8}, "8 minor"},
		{"1.2.3", "1.2.9", Delta{Patch: 6}, "6 patch"},
		{"1.2.3", "3.0.0", Delta{Major: 2}, "2 major"},
		{"1.2.3", "1.2.3", Delta{}, "current"},
		{"1.3.0", "1.2.9", Delta{}, "current"},
	}
	for _, c := range cases {
		d := Gap(MustParse(c.from), MustParse(c.to))
		if d != c.want || d.String() != c.label {
			t.Errorf("Gap(%s,%s) = %+v %q, want %+v %q", c.from, c.to, d, d.String(), c.want, c.label)
		}
	}
	if Gap(MustParse("1.2.3"), MustParse("1.4.0")).Behind() != 2 {
		t.Error("Behind should count the highest non-zero component")
	}
}

func TestUpdateType(t *testing.T) {
	if UpdateType(MustParse("1.2.3"), MustParse("2.0.0")) != "major" ||
		UpdateType(MustParse("1.2.3"), MustParse("1.3.0")) != "minor" ||
		UpdateType(MustParse("1.2.3"), MustParse("1.2.4")) != "patch" {
		t.Error("UpdateType")
	}
}
