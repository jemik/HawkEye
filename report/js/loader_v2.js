var options = {
	rankdir: "LR",
	nodesep: 50, // Increase this value to increase the horizontal separation between nodes
	ranksep: 200, // Increase this value to increase the vertical separation between nodes
};

var g = new dagreD3.graphlib.Graph()
	.setGraph(options)
	.setDefaultEdgeLabel(function () {
		return {};
	});
var proc_data = {}

function connect(ppid, pid) {

	g.setNode(pid, {
		label: "", // Set an empty label: we will create a custom label later
		labelStyle: "fill: #fff; font-weight: 600",
		style: "fill: none; stroke: none; stroke-width: 3px;", // Updated color
		shape: "circle", // Set the shape to circle
		padding: 35, // Adjust padding as necessary
		margin: 47,
		id: pid,
	});

	if (ppid != 0)	// not the parent process
		g.setEdge(ppid, pid, {
			label: proc_data[pid]['injected'] ? "Inject" : "",
			labelStyle: "fill: #f00; font-weight: bold; font-size: 20px;transform: rotate(-30deg);",
			style: "stroke: #424242; stroke-width: 1px; fill: none; " + (proc_data[pid]['injected'] ? "stroke-dasharray: 5, 5;transform: rotate(-30deg);" : ""),
			arrowheadStyle: "fill: #424242",
			curve: d3.curveStep,
		});

	var children = proc_data[pid]['children'];
	if (children.length == 0)
		return;

	for (var i = 0; i < children.length; i++)
		connect(pid, children[i]);
}



function calculateAngle(x1, y1, x2, y2) {
	var deltaX = x2 - x1;
	var deltaY = y2 - y1;
	var rad = Math.atan2(deltaY, deltaX); // In radians
	var deg = rad * (180 / Math.PI);
	return deg;
}

function updateArrowOrientation(pathEl, markerId) {
	var totalLength = pathEl.getTotalLength();
	var midpoint = totalLength / 2;
	var midPoint = pathEl.getPointAtLength(midpoint);
	var previousPoint = pathEl.getPointAtLength(midpoint - 10);
	var nextPoint = pathEl.getPointAtLength(midpoint + 10);

	// Calculate vectors for the previous and next points
	var vectorPrev = { x: previousPoint.x - midPoint.x, y: previousPoint.y - midPoint.y };
	var vectorNext = { x: nextPoint.x - midPoint.x, y: nextPoint.y - midPoint.y };

	// Calculate the cross product of the vectors
	var crossProduct = vectorPrev.x * vectorNext.y - vectorPrev.y * vectorNext.x;

	// If the cross product is close to zero, the points are collinear (straight line)
	if (Math.abs(crossProduct) < 100) {
		// Calculate the angle for the marker
		var angleRad = Math.atan2(nextPoint.y - previousPoint.y, nextPoint.x - previousPoint.x);
		var angleDeg = angleRad * 180 / Math.PI;

		// Adjust the marker position by adding a translate to the existing rotate transform
		var transform = `rotate(-30,${midPoint.x},${midPoint.y})`;

		// Create an invisible line for placing the marker
		var parentNode = d3.select(pathEl.parentNode);
		parentNode.append('line')
			.attr('x1', midPoint.x)
			.attr('y1', midPoint.y)
			.attr('x2', midPoint.x + 1) // Small line segment to ensure a non-zero length for rotation
			.attr('y2', midPoint.y)
			.style('stroke', 'none')
			.style('fill', '#424242')
			.attr('marker-end', `url(#${markerId})`)
			.attr('transform', transform);
	}
}

function getFirstNodeId(graph) {
	var firstNodeId = null;
	graph.nodes().forEach(function (node) {
		// Check if the node has no predecessors
		if (graph.predecessors(node).length === 0) {
			firstNodeId = node;
			return;
		}
	});
	return firstNodeId;
}

function drawProcessFlow(data) {
	proc_data = data;
	connect(0, proc_data["0"]["children"][0]);

	var render = new dagreD3.render();
	var svg = d3.select('svg'),
		svgGroup = svg.append('g');

	render(svgGroup, g);


	var firstNodeId = getFirstNodeId(g); // `g` is your dagreD3 graph instance

	svgGroup.selectAll("g.node").each(function (d) {
		var node = d3.select(this);
		var nodeId = node.attr("id");
		if (nodeId === firstNodeId) {
			appendCustomSVG(node);
		}
	});

	// Get the height of the SVG from the viewBox attribute
	//var svgHeight = svg.node().viewBox.baseVal.height || svg.node().getBoundingClientRect().height;

	var svgHeight = 620;
	console.log('svgHeight : ' + svgHeight);

	// Define the skew and scale based on your desired perspective
	var skewX = -20; // skew angle in degrees
	var scaleY = 0.7; // scale factor (0.0 - 1.0)
	var skewXDegrees = -20; // Adjusted skew angle in degrees
	// Apply perspective effect to each edge
	var edgeCenters = {};
	svgGroup.selectAll('.edgePath path').each(function () {
		var path = d3.select(this);
		var bbox = path.node().getBBox();
		var center = {
			x: bbox.x + bbox.width / 2,
			y: bbox.y + bbox.height / 2
		};

		var transform = `scale(1, ${scaleY}) skewX(${skewX})`;
		path.attr('transform', `translate(${center.x}, ${center.y}) ${transform} translate(${-center.x}, ${-center.y})`);
		// Store the center for later use in node adjustments
		var edgeData = path.data()[0];
		edgeCenters[edgeData.v] = center;
		edgeCenters[edgeData.w] = center;

	});

	// Correct node positions
	svgGroup.selectAll("g.node").each(function () {
		var node = d3.select(this);
		var nodeId = node.attr("id");
		var nodeData = g.node(nodeId);

		// Calculate the skew offset based on the node's original y position
		var skewOffset = Math.tan(skewXDegrees * Math.PI / 180) * (nodeData.y - svgHeight / 4);

		// Calculate a proportional offset for the y-coordinate
		var yOffsetProportion = (nodeData.y - svgHeight / 4) / svgHeight;
		var ySpacingAdjustment = skewOffset * yOffsetProportion;

		// Adjust the node's position by the skew offset and proportional y-spacing
		var newX = nodeData.x + skewOffset;
		var newY = nodeData.y - (scaleY * ySpacingAdjustment);

		// Apply the new position
		node.attr('transform', `translate(${newX}, ${newY})`);
	});

	svgGroup.selectAll('.edgePath path')
		.attr('marker-end', 'url(#standard-arrowhead)');

	//svg.attr('transform', 'rotate(30)');
	// Select all edges and append the arrowhead marker to the middle of the path
	svgGroup.selectAll('.edgePath path').each(function () {
		updateArrowOrientation(this, 'processcreate');
	});

	// Custom rendering for the nodes
	svgGroup.selectAll("g.node").each(function (id) {
		var node = d3.select(this);
		var nodeId = node.attr("id");
		node.attr('data-node-id', nodeId);
		if (id.includes("-label")) { // Skip the label nodes for custom rendering
			return;
		}
		console.log(`Node ${nodeId} - data-node-id set to:`, node.attr('data-node-id'));

		var pid = id;
		createLabelWithBackground(node, proc_data[pid]['name'], 45, "8px", "#e8eff2", "#000", 10, 0);
		createLabelWithBackground(node, "PID: " + pid, 56, "8px", "#e8eff2", "#000", 10, 0);
		// Draw the circle for the node
		node.insert("circle", ":first-child")
			.attr("r", 30) // Set the radius for the circle
			.attr("fill", "#000000")
			.attr("stroke", "#000000")
			.attr("stroke-width", "5px");

		// Append the gear icon as a path and set its color
		var nodebg = "M 49 3 L 96.631393 31.5 L 96.631393 88.5 L 49 117 L 1.368603 88.5 L 1.368603 31.5 Z"
		var nodecenter = "M 50.017544 31 L 73.415421 45 L 73.415421 73 L 50.017544 87 L 26.619665 73 L 26.619665 45 Z"
		var nodecentershadow = "M 50 87 L 50 59 L 73 46 L 73 74 L 50 87 Z"

		node.append("path")
			.attr("d", nodebg) // Your gear path data
			.attr("fill", "#000000") // The fill color for the gear
			.attr("stroke", "#575757")
			.attr("stroke-width", "4px")
			// Adjust the translation values (translateX, translateY) to position the gear
			.attr("transform", (d) => {
				var translateX = -35; // Adjust horizontal position
				var translateY = -15; // Adjust vertical position
				var scale = 0.5; // Adjust the scale if needed
				return `translate(${translateX},${translateY}) scale(${scale}), rotate(-30)`;
			});
		node.append("path")
			.attr("d", nodecenter) // Your gear path data
			.attr("fill", "#ffffff") // The fill color for the gear
			// Adjust the translation values (translateX, translateY) to position the gear
			.attr("transform", (d) => {
				var translateX = -35; // Adjust horizontal position
				var translateY = -15; // Adjust vertical position
				var scale = 0.5; // Adjust the scale if needed
				return `translate(${translateX},${translateY}) scale(${scale}), rotate(-30)`;
			});
		node.append("path")
			.attr("d", nodecentershadow) // Your gear path data
			.attr("fill", "#151515") // The fill color for the gear
			.attr("opacity", "0.15")
			// Adjust the translation values (translateX, translateY) to position the gear
			.attr("transform", (d) => {
				var translateX = -35; // Adjust horizontal position
				var translateY = -15; // Adjust vertical position
				var scale = 0.5; // Adjust the scale if needed
				return `translate(${translateX},${translateY}) scale(${scale}), rotate(-30)`;
			});


	});



	adjustNodePositions(svgGroup, skewX, scaleY);

	var xCenterOffset = (svg.attr('width') - g.graph().width + 100) / 2;
	svgGroup.attr('transform', 'translate(' + xCenterOffset + ', 0)');
	svg.attr('height', g.graph().height * 2);
	const elem = document.getElementById('panzoom-element')
	const panzoom = Panzoom(elem, {
		maxScale: 5,
		step: 0.18,
	});

	const processzoomInButton = document.getElementById('processzoomInButton');
	const processzoomOutButton = document.getElementById('processzoomOutButton');
	const processresetButton = document.getElementById('processresetButton');
	processzoomInButton.addEventListener('click', panzoom.zoomIn);
	processzoomOutButton.addEventListener('click', panzoom.zoomOut);
	processresetButton.addEventListener('click', panzoom.reset);

	// const parent = elem.parentElement;
	// parent.addEventListener('wheel', panzoom.zoomWithWheel);
	// parent.addEventListener('wheel', function(event) {
	//   if (!event.shiftKey) return
	//   panzoom.zoomWithWheel(event)
	// });
	document.getElementById('fullscreenButton').addEventListener('click', toggleFullScreen);
	document.addEventListener('keydown', handleKeyDown);

}

function createLabelWithBackground(node, text, dy, fontSize, rectColor, fontcolor, rectHeight, rectYOffset) {
	// Append text to get the length
	var textElement = node.append("text")
		.text(text)
		.attr("text-anchor", "start")
		.style("fill", fontcolor)
		.style("font-size", fontSize)
		.attr('transform', 'rotate(-30)')
		.style('text-transform', 'uppercase')
		.attr("dx", "1")
		.attr("dy", dy);

	// Get the length of the text
	var bbox = textElement.node().getBBox();
	var textLength = bbox.width;
	// Append the background rectangle based on text length
	node.insert("rect", ":first-child")
		//.attr("x", -(textLength / 2))
		.attr("x", "0")
		.attr("y", bbox.y - rectYOffset) // Adjust based on where you want the rectangle
		.attr("width", textLength + 2)
		.attr("height", rectHeight)
		.attr("fill", rectColor)
		.attr("transform", 'rotate(-30)');

	// Re-append the text so it's on top of the rectangle
	textElement.remove();
	node.append(() => textElement.node()); // Re-add the text element

}


function adjustNodePositions(svgGroup, skewX, scaleY) {
	// Iterate over each node
	svgGroup.selectAll('g.node').each(function () {
		var node = d3.select(this);
		var nodeId = node.attr('data-node-id');

		// Retrieve all edges connected to this node
		var connectedEdges = svgGroup.selectAll(`.edgePath[source-node-id="${nodeId}"], .edgePath[target-node-id="${nodeId}"]`);

		connectedEdges.each(function () {
			var edge = d3.select(this);
			var path = edge.select('path');
			var totalLength = path.node().getTotalLength();

			// Determine the correct endpoint based on whether the node is a source or a target
			var point;
			if (edge.attr('source-node-id') === nodeId) {
				// If the node is the source, get the start point of the path
				point = path.node().getPointAtLength(0);
			} else {
				// If the node is the target, get the end point of the path
				point = path.node().getPointAtLength(totalLength);
			}

			// Calculate the reverse of the skew transformation
			var rad = skewX * (Math.PI / 180);
			var tan = Math.tan(rad);

			// Correct the endpoint's position based on the transformations
			var correctedX = point.x - point.y * tan;
			var correctedY = point.y / scaleY;

			// Adjust node position
			node.attr('transform', `translate(${correctedX}, ${correctedY})`);
		});
	});
}


function toggleFullScreen() {
	var graphDiv = document.getElementById('process-graph');

	// Check if we are currently in full screen mode
	if (graphDiv.style.position === 'fixed') {
		// If we are in full screen mode, revert to the default styles
		graphDiv.style.position = '';
		graphDiv.style.top = '';
		graphDiv.style.left = '';
		graphDiv.style.width = '';
		graphDiv.style.height = '';
		graphDiv.style.maxHeight = '500px';
		graphDiv.style.zIndex = '';
		graphDiv.style.overflow = 'hidden';
	} else {
		// If we are not in full screen mode, apply full screen styles
		graphDiv.style.position = 'fixed';
		graphDiv.style.top = '0';
		graphDiv.style.left = '0';
		graphDiv.style.width = '100%';
		graphDiv.style.height = '100%';
		graphDiv.style.zIndex = '9999';
		graphDiv.style.overflow = 'auto';
		graphDiv.style.background = '#000000';
		graphDiv.style.overflow = 'hidden';
		graphDiv.style.maxHeight = '';
	}
}

function handleKeyDown(event) {
	var graphDiv = document.getElementById('process-graph');

	// Check if the key pressed is the Escape key
	if (event.key === "Escape" || event.keyCode === 27) {
		// Check if we are currently in full screen mode
		if (graphDiv.style.position === 'fixed') {
			toggleFullScreen(); // Call the function to exit full screen
		}
	}
}

function appendCustomSVG(node) {
	// Append a new group element to the node to hold the custom SVG
	var customGroup = node.append('g')
		.attr('transform', 'translate(5, -65), rotate(-30), scale(0.4)'); // Center the SVG on the node

	// Background rectangle for "SAMPLE EXECUTED"
	customGroup.append('rect')
		.attr('x', 0)
		.attr('y', 71)
		.attr('width', 199)
		.attr('height', 23)
		.attr('fill', '#e8eff2');

	// Text "SAMPLE EXECUTED"
	customGroup.append('text')
		.attr('x', 0) // Padding from the left side
		.attr('y', 90)
		.attr('font-family', 'Arial')
		.attr('font-size', 20)
		.attr('fill', '#000000')
		.text('SAMPLE EXECUTED');

	// Rectangle for "PROCESS BEHAVIOUR"
	customGroup.append('rect')
		.attr('x', 0)
		.attr('y', 96)
		.attr('width', 225)
		.attr('height', 24)
		.attr('fill', '#e8eff2');

	// Text "PROCESS BEHAVIOUR"
	customGroup.append('text')
		.attr('x', 0) // Padding from the left side
		.attr('y', 114)
		.attr('font-family', 'Arial')
		.attr('font-size', 20)
		.attr('fill', '#000000')
		.text('PROCESS BEHAVIOUR');

	// For the SHA256 and the hash value, you can continue appending text elements as needed.
	customGroup.append('text')
		.attr('x', 51)
		.attr('y', 23)
		.attr('font-family', 'Arial')
		.attr('font-size', 20)
		.attr('font-weight', 'bold')
		.attr('fill', '#575757')
		.text('SHA256');

	customGroup.append('text')
		.attr('x', 51)
		.attr('y', 58)
		.attr('font-family', 'Arial')
		.attr('font-size', 24)
		.attr('font-weight', 'bold')
		.attr('fill', '#ffffff')
		.text('86b5d7dd88b46a3e7c2fb58c01fbeb11dc7ad350370abfe648dbfad45edb8132');


	customGroup.append("path")
		.attr('fill', '#ffffff')
		.attr("d", "M 1 62 L 1 58.666016 L 7.666016 58.666016 L 7.666016 45.333984 L 2.666016 45.333984 L 2.666016 42 L 4.333984 42 C 5.245099 42 6.028035 41.673134 6.683594 41.017578 C 7.339152 40.362015 7.666016 39.577133 7.666016 38.666016 L 11 38.666016 L 11 58.666016 L 17.666016 58.666016 L 17.666016 62 L 1 62 Z M 27.666016 62 C 25.843786 62 24.277912 61.344322 22.966797 60.033203 C 21.65568 58.722088 21 57.156212 21 55.333984 L 21 45.333984 C 21 43.511749 21.65568 41.943932 22.966797 40.632813 C 24.277912 39.321701 25.843786 38.666016 27.666016 38.666016 L 31 38.666016 C 32.822231 38.666016 34.3881 39.321701 35.699219 40.632813 C 37.010334 41.943932 37.666016 43.511749 37.666016 45.333984 L 37.666016 55.333984 C 37.666016 57.156212 37.010334 58.722088 35.699219 60.033203 C 34.3881 61.344322 32.822231 62 31 62 L 27.666016 62 Z M 27.666016 58.666016 L 31 58.666016 C 31.911116 58.666016 32.694054 58.339153 33.349609 57.683594 C 34.005169 57.028034 34.333984 56.245098 34.333984 55.333984 L 34.333984 47.699219 L 24.900391 57.132813 C 25.56706 58.155037 26.488234 58.666016 27.666016 58.666016 Z M 24.333984 53.033203 L 33.833984 43.533203 C 33.167316 42.510979 32.222229 42 31 42 L 27.666016 42 C 26.7549 42 25.971964 42.326859 25.316406 42.982422 C 24.660847 43.637978 24.333984 44.422867 24.333984 45.333984 L 24.333984 53.033203 Z M 7.666016 30 C 5.843786 30 4.277913 29.344322 2.966797 28.033203 C 1.655681 26.722084 1 25.156212 1 23.333984 L 1 13.333984 C 1 11.511749 1.655681 9.943932 2.966797 8.632813 C 4.277913 7.321693 5.843786 6.666016 7.666016 6.666016 L 11 6.666016 C 12.822229 6.666016 14.388103 7.321693 15.699219 8.632813 C 17.010336 9.943932 17.666016 11.511749 17.666016 13.333984 L 17.666016 23.333984 C 17.666016 25.156212 17.010336 26.722084 15.699219 28.033203 C 14.388103 29.344322 12.822229 30 11 30 L 7.666016 30 Z M 21 30 L 21 26.666016 L 27.666016 26.666016 L 27.666016 13.333984 L 22.666016 13.333984 L 22.666016 10 L 24.333984 10 C 25.2451 10 26.028036 9.673134 26.683594 9.017578 C 27.339153 8.362015 27.666016 7.577133 27.666016 6.666016 L 31 6.666016 L 31 26.666016 L 37.666016 26.666016 L 37.666016 30 L 21 30 Z M 7.666016 26.666016 L 11 26.666016 C 11.911115 26.666016 12.694051 26.339149 13.349609 25.683594 C 14.005167 25.02803 14.333984 24.245094 14.333984 23.333984 L 14.333984 15.699219 L 4.900391 25.132813 C 5.56706 26.155045 6.488233 26.666016 7.666016 26.666016 Z M 4.333984 21.033203 L 13.833984 11.533203 C 13.167315 10.510979 12.222227 10 11 10 L 7.666016 10 C 6.754901 10 5.971965 10.326866 5.316406 10.982422 C 4.660848 11.637985 4.333984 12.422867 4.333984 13.333984 L 4.333984 21.033203 Z");


}


function fillFileActivity(data) {
	var created = document.getElementById("file-created");
	var modified = document.getElementById("file-modified");
	var deleted = document.getElementById("file-deleted");
	var moved = document.getElementById("file-moved");
	var copied = document.getElementById("file-copied");

	created.innerHTML += (data["created"].length <= 100 ? `(${data["created"].length})` : "(100+)");
	modified.innerHTML += (data["modified"].length <= 100 ? `(${data["modified"].length})` : "(100+)");
	deleted.innerHTML += (data["deleted"].length <= 100 ? `(${data["deleted"].length})` : "(100+)");
	moved.innerHTML += (data["moved"].length <= 100 ? `(${data["moved"].length})` : "(100+)");
	copied.innerHTML += (data["copied"].length <= 100 ? `(${data["copied"].length})` : "(100+)");

	var createdList = document.getElementById("file-created-list");
	var modifiedList = document.getElementById("file-modified-list");
	var deletedList = document.getElementById("file-deleted-list");
	var movedList = document.getElementById("file-moved-list");
	var copiedList = document.getElementById("file-copied-list");

	data["created"].some(function (filePath, idx) {
		createdList.innerHTML += `<li class="list-group-item">${filePath}</li>`;
		return idx == 100;
	});
	data["modified"].some(function (filePath, idx) {
		modifiedList.innerHTML += `<li class="list-group-item">${filePath}</li>`;
		return idx == 100;
	});
	data["deleted"].some(function (filePath, idx) {
		deletedList.innerHTML += `<li class="list-group-item">${filePath}</li>`;
		return idx == 100;
	});
	data["moved"].some(function (fileFromTo, idx) {
		movedList.innerHTML += `<li class="list-group-item">${fileFromTo['from']}  &nbsp;&nbsp; &rarr; &nbsp;&nbsp; ${fileFromTo['to']}</li>`;
		return idx == 100;
	});
	data["copied"].some(function (fileFromTo, idx) {
		copiedList.innerHTML += `<li class="list-group-item">${fileFromTo['from']} &nbsp;&nbsp; &rarr; &nbsp;&nbsp; ${fileFromTo['to']}</li>`;
		return idx == 100;
	});
}

function fillNetworkActivity(data) {
	document.getElementById("network-urls").innerHTML += `(${data["urls"].length})`;
	document.getElementById("network-dns").innerHTML += `(${data["dns"].length})`;

	var urlsList = document.getElementById("network-urls-list");
	var dnsList = document.getElementById("network-dns-list");

	data["urls"].forEach(function (url) {
		urlsList.innerHTML += `<li class="list-group-item">${url}</li>`;
	});
	data["dns"].forEach(function (domain) {
		dnsList.innerHTML += `<li class="list-group-item">${domain}</li>`;
	});
}

function fillRegistryActivity(data) {
	var set = document.getElementById("registry-set");
	var queried = document.getElementById("registry-queried");
	var deleted = document.getElementById("registry-deleted");

	set.innerHTML += (data["set"].length <= 100 ? `(${data["set"].length})` : "(100+)");
	queried.innerHTML += (data["queried"].length <= 100 ? `(${data["queried"].length})` : "(100+)");
	deleted.innerHTML += (data["deleted"].length <= 100 ? `(${data["deleted"].length})` : "(100+)");

	var setList = document.getElementById("registry-set-list");
	var queriedList = document.getElementById("registry-queried-list");
	var deletedList = document.getElementById("registry-deleted-list");

	data["set"].some(function (regval, idx) {
		setList.innerHTML += `<li class="list-group-item">${regval}</li>`;
		return idx == 100;
	});
	data["queried"].some(function (regval, idx) {
		queriedList.innerHTML += `<li class="list-group-item">${regval}</li>`;
		return idx == 100;
	});
	data["deleted"].some(function (regval, idx) {
		deletedList.innerHTML += `<li class="list-group-item">${regval}</li>`;
		return idx == 100;
	});
}

function fillGeneralActivity(data) {
	document.getElementById("general-commands").innerHTML += `(${data["commands"].length})`;
	document.getElementById("general-imports").innerHTML += `(${data["imports"].length})`;
	document.getElementById("general-mutexes").innerHTML += `(${data["mutexes"].length})`;

	var commandsList = document.getElementById("general-commands-list");
	var importsList = document.getElementById("general-imports-list");
	var mutexesList = document.getElementById("general-mutexes-list");

	data["commands"].forEach(function (command) {
		commandsList.innerHTML += `<li class="list-group-item">${command}</li>`;
	});
	data["imports"].forEach(function (api) {
		importsList.innerHTML += `<li class="list-group-item">${api}</li>`;
	});
	data["mutexes"].forEach(function (mutex) {
		mutexesList.innerHTML += `<li class="list-group-item">${mutex}</li>`;
	});
}

$.getJSON("/output/data.json").then(function (data) {
	drawProcessFlow(data["processes"]);
	fillFileActivity(data["files"]);
	fillNetworkActivity(data["network"]);
	fillRegistryActivity(data["registry"]);
	fillGeneralActivity(data["general"]);
});