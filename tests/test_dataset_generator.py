"""Tests for ml.dataset_generator.augment_labeled_samples — uploaded-data augmentation."""

from ml.dataset_generator import augment_labeled_samples


def _sample(label=1, attack_type='sqli'):
    return {
        'method': 'GET',
        'url': "/login?user=admin&pass=' OR '1'='1",
        'headers': {'User-Agent': 'Mozilla/5.0'},
        'body': '',
        'ip': '203.0.113.10',
        'label': label,
        'attack_type': attack_type,
    }


def test_augment_returns_originals_plus_variants():
    samples = [_sample(), _sample(label=0, attack_type='normal')]
    result = augment_labeled_samples(samples, variants_per_sample=5)

    assert len(result) == len(samples) * (5 + 1)
    # Originals are preserved unchanged.
    for original in samples:
        assert original in result


def test_augment_preserves_label_and_attack_type():
    samples = [_sample(label=1, attack_type='sqli')]
    result = augment_labeled_samples(samples, variants_per_sample=5)

    for row in result:
        assert row['label'] == 1
        assert row['attack_type'] == 'sqli'


def test_augment_variants_have_required_keys():
    samples = [_sample()]
    result = augment_labeled_samples(samples, variants_per_sample=3)

    for row in result:
        for key in ('method', 'url', 'headers', 'body', 'ip', 'label', 'attack_type'):
            assert key in row


def test_augment_zero_variants_returns_only_originals():
    samples = [_sample(), _sample(label=0, attack_type='normal')]
    result = augment_labeled_samples(samples, variants_per_sample=0)

    assert result == samples
