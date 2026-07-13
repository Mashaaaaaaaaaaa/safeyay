# SPDX-License-Identifier: GPL-3.0-or-later
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent


class InstallerTests(unittest.TestCase):
    def test_user_install_still_finds_scanner_after_prefix_moves(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            original = temporary / "old-home" / ".local"
            moved = temporary / "new-home" / ".local"
            env = os.environ.copy()
            env["PREFIX"] = str(original)
            subprocess.run([str(ROOT / "install.sh")], env=env, check=True, capture_output=True, text=True)

            moved.parent.mkdir()
            shutil.move(original, moved)
            fake_bin = temporary / "fake-bin"
            fake_bin.mkdir()
            arguments = temporary / "yay-arguments"
            fake_yay = fake_bin / "yay"
            fake_yay.write_text(f'#!/usr/bin/env bash\nprintf "%s\\n" "$@" > "{arguments}"\n')
            fake_yay.chmod(0o755)

            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            completed = subprocess.run(
                [str(moved / "bin/safeyay"), "-S", "demo"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            invoked = arguments.read_text().splitlines()
            scanner = invoked[invoked.index("--editor") + 1]
            self.assertEqual(Path(scanner).resolve(), moved / "lib/safeyay/safeyay_scanner.py")
            self.assertNotIn(str(original), (moved / "bin/safeyay").read_text())


if __name__ == "__main__":
    unittest.main()
