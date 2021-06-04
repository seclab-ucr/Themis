.. BTest-Sphinx Demo documentation master file, created by
   sphinx-quickstart on Wed May  8 15:22:37 2013.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to BTest-Sphinx Demo's documentation!
=============================================

Contents:

.. toctree::
   :maxdepth: 2

Testing
=======

.. btest:: hello-world

    @TEST-EXEC: btest-rst-cmd echo "Hello, world!"

.. btest:: hello-world

    @TEST-EXEC: btest-rst-cmd echo "Hello, world! Again."

.. btest:: hello-world

    @TEST-EXEC: btest-rst-cmd echo "Hello, world! Again. Again."

.. btest:: hello-world-fail

    @TEST-EXEC: btest-rst-cmd echo "This will fail soon!"

This should fail and include the diag output instead:

.. btest:: hello-world-fail

    @TEST-EXEC: echo StDeRr >&2; echo 1 | grep -q 2

This should succeed:

.. btest:: hello-world-fail

    @TEST-EXEC: btest-rst-cmd echo "This succeeds again!"

This should fail again and include the diag output instead:

.. btest:: hello-world-fail

    @TEST-EXEC: echo StDeRr >&2; echo 3 | grep -q 4

.. btest:: hello-world-fail

    @TEST-EXEC: btest-rst-cmd echo "This succeeds again!"

.. btest-include:: btest.cfg


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

