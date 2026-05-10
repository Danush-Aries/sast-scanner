import json
from typing import List, Dict, Any
from sarif_om import SarifLog, Run, Result, Location, Region, ArtifactLocation, Tool, ToolComponent, PhysicalLocation

class SarifExporter:
    def export(self, findings: List[Dict[str, Any]], output_path: str):
        # Create SARIF structure
        driver = ToolComponent(
            name="SAST-Scanner",
            version="1.0.0"
        )
        tool = Tool(driver=driver)
        run = Run(tool=tool)

        results = []
        for f in findings:
            # Correctly nesting: Location -> PhysicalLocation -> ArtifactLocation & Region
            region = Region(start_line=f["line"])
            artifact_location = ArtifactLocation(uri=f["file"])
            physical_location = PhysicalLocation(artifact_location=artifact_location, region=region)
            
            # The Location object itself wraps the physical_location
            sarif_location = Location(physical_location=physical_location)

            results.append(Result(
                message={"text": f["message"]},
                rule_id=f["id"],
                locations=[
                    sarif_location
                ]
            ))

        run.results = results
        sarif_log = SarifLog(version="2.1.0", runs=[run])

        try:
            import sarif_om.serializer
            serialized_log = sarif_om.serializer.serialize(sarif_log)
            with open(output_path, "w") as f:
                f.write(json.dumps(serialized_log, indent=2))
        except (ImportError, AttributeError):
            with open(output_path, "w") as f:
                f.write(json.dumps(sarif_log, default=lambda o: o.__dict__, indent=2))
