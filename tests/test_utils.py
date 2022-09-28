from memobj import utils


def test_pad_format():
    assert utils.pad_format("<bib") == "<bxxxibxxx"
    assert utils.pad_format("<bqb") == "<bxxxxxxxqbxxxxxxx"
    assert utils.pad_format("<lhh") == "<lhh"
    assert utils.pad_format("<clh") == "<cxxxlhxx"
