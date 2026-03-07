from quevidkit.models import AnalysisOptions


def test_options_clamp_values():
    options = AnalysisOptions.from_dict(
        {
            "preset": "balanced",
            "sample_fps": 999,
            "max_frames": 10,
            "sensitivity": 10,
        }
    )
    assert options.sample_fps == 30.0
    assert options.max_frames == 60
    assert options.sensitivity == 0.99


def test_deep_preset_applies():
    options = AnalysisOptions.from_dict({"preset": "deep", "sample_fps": 1.0, "max_frames": 100})
    assert options.sample_fps >= 4.0
    assert options.max_frames >= 5000


def test_invalid_numeric_option_raises_value_error():
    try:
        AnalysisOptions.from_dict({"sample_fps": "bad-value"})
    except ValueError:
        return
    assert False, "Expected ValueError for invalid numeric payload"
