import pspdisasm


def test_phase8a_workspace_and_pack_helpers_are_public_api():
    assert pspdisasm.GameWorkspaceManifest is not None
    assert pspdisasm.WorkspaceFileRecord is not None
    assert pspdisasm.WorkspaceAnalysisResult is not None
    assert pspdisasm.prepare_game_workspace is not None
    assert pspdisasm.load_game_workspace is not None
    assert pspdisasm.analyze_game_workspace is not None
    assert pspdisasm.AnalysisPackResult is not None
    assert pspdisasm.create_analysis_pack is not None
    for name in (
        "GameWorkspaceManifest",
        "WorkspaceFileRecord",
        "WorkspaceAnalysisResult",
        "prepare_game_workspace",
        "load_game_workspace",
        "analyze_game_workspace",
        "AnalysisPackResult",
        "create_analysis_pack",
    ):
        assert name in pspdisasm.__all__
