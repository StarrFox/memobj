from memobj import utils


def test_pad_format():
    assert utils.pad_format("<bib") == "<bxxxibxxx"
    assert utils.pad_format("<bqb") == "<bxxxxxxxqbxxxxxxx"
